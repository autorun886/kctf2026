#include <jni.h>
#include <stdint.h>
#include <string.h>
#include "include/kctf.h"
#include "include/const_xor.h"

/* ── 硬编码 IV（方案 B）─────────────────────────────────── */
static volatile const uint8_t IV[STATE_LEN] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
};

/* 方案 B 第一次 SPN 目标（XOR 加密存储，converge.py 填入） */
static volatile const uint8_t ENC_EXPECTED_STATE_ENC[STATE_LEN] = {
    0x19, 0x9E, 0x5B, 0xB3, 0x69, 0x80, 0xD4, 0x56,
    0x7A, 0xA4, 0xC8, 0x8C, 0x52, 0xD9, 0x95, 0x47
};

/* ── 第二 IV（唯一性约束，与 IV1 不同）──────────────────── */
static volatile const uint8_t IV2[STATE_LEN] = {
    0xA5,0x5A,0xC3,0x3C,0xF0,0x0F,0x69,0x96,
    0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0
};

/* 方案 B 第二次 SPN 目标（XOR 加密存储，converge.py 填入） */
static volatile const uint8_t ENC_EXPECTED_STATE2_ENC[STATE_LEN] = {
    0x82, 0x85, 0xD0, 0x2D, 0x47, 0x35, 0xE9, 0x14,
    0xB7, 0xC7, 0x41, 0x0E, 0xBB, 0x6A, 0xDD, 0xE9
};

/* const_xor piece 2: LE_u32(IV[0:4]) ^ LE_u32(IV2[0:4]) — 耦合到 const_xor.c */
uint32_t cxk_get_piece2(void) {
    uint32_t a = (uint32_t)IV[0] | ((uint32_t)IV[1] << 8)
              | ((uint32_t)IV[2] << 16) | ((uint32_t)IV[3] << 24);
    uint32_t b = (uint32_t)IV2[0] | ((uint32_t)IV2[1] << 8)
              | ((uint32_t)IV2[2] << 16) | ((uint32_t)IV2[3] << 24);
    return a ^ b;
}

/* 方案 A 目标状态（XOR 加密存储，converge.py 填入） */
static volatile const uint8_t ENC_EXPECTED_STATE_A_ENC[STATE_LEN] = {
    0x7C, 0x94, 0xDE, 0x96, 0xE6, 0x73, 0x40, 0xDA,
    0xFA, 0xBE, 0x5A, 0x2D, 0xD3, 0x72, 0xDA, 0x5B
};

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint8_t sokey_share_mask(int i) {
    return (uint8_t)(((0x6Du + (uint32_t)i * 0x3Bu) ^ ((uint32_t)i * 0x1Du)) & 0xFFu);
}

/* ── JNI 回调获取 soKey ──────────────────────────────────── */
static void fetch_sokey(JNIEnv *env, jobject obj, uint8_t out[SOKEY_LEN]) {
    (void)kctf_guard_anchor();
    jclass    clazz = (*env)->GetObjectClass(env, obj);
    jmethodID mid   = (*env)->GetMethodID(env, clazz, "deriveNativeKey", "()[B");
    jbyteArray jarr = (jbyteArray)(*env)->CallObjectMethod(env, obj, mid);
    uint8_t meta[28] = {0};
    jsize len = jarr ? (*env)->GetArrayLength(env, jarr) : 0;
    jsize copy_len = (len < (jsize)sizeof(meta)) ? len : (jsize)sizeof(meta);
    if (copy_len > 0)
        (*env)->GetByteArrayRegion(env, jarr, 0, copy_len, (jbyte *)meta);
    memcpy(out, meta, SOKEY_LEN);
    for (int i = 0; i < SOKEY_LEN; i++)
        out[i] ^= sokey_share_mask(i);

    if (len >= 28) {
        uint32_t apk_crc  = load_le32(meta + 16);
        uint32_t text_off = load_le32(meta + 20);
        uint32_t text_len = load_le32(meta + 24);
        uint32_t mem_crc  = kctf_runtime_text_crc(text_off, text_len);
        uint32_t diff = apk_crc ^ mem_crc;
        uint32_t poison = ((diff | (~diff + 1u)) >> 31) * 0x9E3779B9u;
        for (int i = 0; i < SOKEY_LEN; i++)
            out[i] ^= (uint8_t)(poison >> ((i & 3) * 8));
    } else {
        for (int i = 0; i < SOKEY_LEN; i++)
            out[i] ^= (uint8_t)(0xA5u + i * 17u);
    }
    secure_bzero(meta, sizeof(meta));
    if (jarr) (*env)->DeleteLocalRef(env, jarr);
    (*env)->DeleteLocalRef(env, clazz);
}

/* ── 方案 A 内部验证（不导出为 JNI）────────────────────── */
static int verify_scheme_a(const uint8_t *flagA, const uint8_t *soKey) {
    /* 修复链 */
    repair_cfg(flagA, soKey);

    extern uint32_t dispatch_table[4];
    uint8_t cfg_dep = (uint8_t)(dispatch_table[0] & 0xFFu);
    repair_sbox(flagA, cfg_dep);

    extern uint8_t sbox_shipped[256];
    uint8_t sbox_first = sbox_shipped[0];
    repair_constants(flagA, sbox_first);

    extern uint32_t round_constants[32];
    uint8_t rc_high4 = (uint8_t)(round_constants[0] >> 28);
    repair_semantics(flagA, rc_high4);

    /* 执行 BB0~BB7 */
    uint32_t state32[4] = {0, 0, 0, 0};
    core_compute(state32);

    uint8_t final_state[STATE_LEN];
    for (int i = 0; i < 4; i++) {
        final_state[i*4+0] = (uint8_t)(state32[i]      );
        final_state[i*4+1] = (uint8_t)(state32[i] >>  8);
        final_state[i*4+2] = (uint8_t)(state32[i] >> 16);
        final_state[i*4+3] = (uint8_t)(state32[i] >> 24);
    }

    uint8_t expected[STATE_LEN];
    const_xor_load(expected, (const uint8_t *)ENC_EXPECTED_STATE_A_ENC, STATE_LEN);
    for (int i = 0; i < STATE_LEN; i++)
        expected[i] ^= soKey[i];

    volatile uint8_t diff = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff |= final_state[i] ^ expected[i];

    secure_bzero(final_state, sizeof(final_state));
    secure_bzero(expected, sizeof(expected));
    secure_bzero(state32, sizeof(state32));
    return (diff == 0) ? 1 : 0;
}

/* ── 密钥派生辅助函数（诱导选手 hook）─────────────────────
 * 这些函数在正确路径中被调用，返回值参与最终验证。
 * 选手看到函数名会想 hook 它们获取中间密钥，
 * 但 hook 行为会触发蜜罐 F（inline hook 检测）。
 * 函数内部逻辑故意复杂化，让选手觉得"hook 比逆向更划算"。
 */

/* 从 soKey 派生 session token — 看起来像"解密主密钥" */
static void get_session_token(const uint8_t *soKey, const uint8_t *material,
                              uint8_t out[16]) {
    /* HMAC-like 结构（实际是简单 XOR + 旋转，但看起来很复杂） */
    uint32_t state[4];
    for (int i = 0; i < 4; i++)
        state[i] = ((uint32_t)soKey[i*4] << 24) | ((uint32_t)soKey[i*4+1] << 16) |
                   ((uint32_t)soKey[i*4+2] << 8) | (uint32_t)soKey[i*4+3];

    /* 8 轮"密钥调度"（实际只是混合 material） */
    for (int r = 0; r < 8; r++) {
        uint32_t m = ((uint32_t)material[r*4] << 24) | ((uint32_t)material[r*4+1] << 16) |
                     ((uint32_t)material[r*4+2] << 8) | (uint32_t)material[r*4+3];
        state[r & 3] ^= m;
        state[(r+1) & 3] += state[r & 3];
        state[(r+2) & 3] ^= (state[(r+1) & 3] >> 7) | (state[(r+1) & 3] << 25);
    }

    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(state[i] >> 24);
        out[i*4+1] = (uint8_t)(state[i] >> 16);
        out[i*4+2] = (uint8_t)(state[i] >> 8);
        out[i*4+3] = (uint8_t)(state[i]);
    }
}

/* 从 session token 派生 verification key — 看起来像"最终比对密钥" */
static void derive_verification_key(const uint8_t *token, const uint8_t *iv,
                                    uint8_t out[16]) {
    /* "AES-like key whitening"（实际是 XOR + 字节旋转） */
    for (int i = 0; i < 16; i++)
        out[i] = token[i] ^ iv[i] ^ token[(i + 7) & 0xF];

    /* "Key stretching"（4 轮自混合） */
    for (int r = 0; r < 4; r++) {
        uint8_t tmp = out[0];
        for (int i = 0; i < 15; i++)
            out[i] = out[i] ^ out[i+1] ^ (uint8_t)(r * 0x37 + i);
        out[15] = out[15] ^ tmp ^ (uint8_t)(r * 0x37 + 15);
    }
}

/* ── 方案 B 内部验证 ─────────────────────────────────────── */
static int verify_scheme_b(const uint8_t *flagB, const uint8_t *soKey) {
    struct runtime_params params;
    key_schedule(flagB, soKey, &params);

    /* Oracle 比对：shellcode 返回 seeds[16] + material[0:8] + tag[8].
     * 不暴露完整 material[0:16]，避免直接补齐 ARX 末态后逆回 flag。 */
    extern volatile uint8_t g_sokey_for_oracle[16];
    for (int i = 0; i < 16; i++)
        g_sokey_for_oracle[i] = soKey[i];

    uint8_t oracle_data[32] = {0};
    int oracle_status = get_oracle_material(oracle_data);

    /* oracle_data[0:16] = seeds, oracle_data[16:24] = material[0:8],
     * oracle_data[24:32] = tag(seeds, soKey). */
    /* 验证 seeds */
    volatile uint8_t seeds_diff = 0;
    uint8_t *expected_seeds = (uint8_t *)params.sbox_seeds;
    for (int i = 0; i < 16; i++)
        seeds_diff |= expected_seeds[i] ^ oracle_data[i];

    /* 验证 material[0:8]。后 8 字节不暴露，保留约束求解门槛。 */
    uint8_t material_head[16];
    expand_key_material(flagB, material_head, 16);
    volatile uint8_t mat_diff = 0;
    for (int i = 0; i < 8; i++)
        mat_diff |= material_head[i] ^ oracle_data[16 + i];

    volatile uint8_t tag_diff = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t tag = (uint8_t)(oracle_data[i] ^ oracle_data[8 + i] ^
                                soKey[(i + 5) & 0x0F] ^ (uint8_t)(0xC3u + i * 0x29u));
        tag_diff |= tag ^ oracle_data[24 + i];
    }

    uint8_t sboxes[SPN_SBOXES][256];
    for (int i = 0; i < SPN_SBOXES; i++)
        generate_sbox(params.sbox_seeds[i], sboxes[i]);

    /* 第一次 SPN（IV1）*/
    uint8_t state[STATE_LEN];
    memcpy(state, IV, STATE_LEN);
    spn_encrypt(state, &params, sboxes);

    uint8_t expected[STATE_LEN];
    const_xor_load(expected, (const uint8_t *)ENC_EXPECTED_STATE_ENC, STATE_LEN);
    for (int i = 0; i < STATE_LEN; i++)
        expected[i] ^= soKey[i];

    volatile uint8_t diff = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff |= state[i] ^ expected[i];

    /* 第二次 SPN（IV2）：总约束 256 bit > 200 bit，保证唯一性 */
    uint8_t state2[STATE_LEN];
    memcpy(state2, IV2, STATE_LEN);
    spn_encrypt(state2, &params, sboxes);

    uint8_t expected2[STATE_LEN];
    const_xor_load(expected2, (const uint8_t *)ENC_EXPECTED_STATE2_ENC, STATE_LEN);
    for (int i = 0; i < STATE_LEN; i++)
        expected2[i] ^= soKey[i];

    volatile uint8_t diff2 = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff2 |= state2[i] ^ expected2[i];

    uint8_t oracle_diff = (uint8_t)((oracle_status != 0) ? 0xFFu : 0u);
    uint8_t ok = (uint8_t)(diff | diff2 | seeds_diff | mat_diff | tag_diff | oracle_diff);

    secure_bzero(&params, sizeof(params));
    secure_bzero(oracle_data, sizeof(oracle_data));
    secure_bzero(material_head, sizeof(material_head));
    secure_bzero(sboxes, sizeof(sboxes));
    secure_bzero(state, sizeof(state));
    secure_bzero(expected, sizeof(expected));
    secure_bzero(state2, sizeof(state2));
    secure_bzero(expected2, sizeof(expected2));

    return (ok == 0) ? 1 : 0;
}

/*
 * nativeProcessInput — 主入口
 *
 * 输入：50 字节交错 flag
 *   input[i*2]   → flagA[i]  (i=0..24)  方案 A
 *   input[i*2+1] → flagB[i]  (i=0..24)  方案 B
 *
 * 顺序依赖：方案 A 通过后才运行方案 B。
 * 方案 A 失败 → 返回 0（不泄露是哪个方案失败）。
 */
JNIEXPORT jint JNICALL
Java_com_autorun_kctf_MainActivity_nativeProcessInput(
        JNIEnv *env, jobject obj, jbyteArray jflag) {

    /* 1. 提取 50 字节 */
    uint8_t input[FLAG_LEN];
    (*env)->GetByteArrayRegion(env, jflag, 0, FLAG_LEN, (jbyte *)input);

    /* 2. 交错拆分 */
    uint8_t flagA[FLAG_HALF], flagB[FLAG_HALF];
    for (int i = 0; i < FLAG_HALF; i++) {
        flagA[i] = input[i * 2];
        flagB[i] = input[i * 2 + 1];
    }

    /* 不透明谓词：用 input[0] 驱动花指令条件。
     * IDA 不知道输入值 → 无法确定花指令分支方向。
     * 选手不能 patch 此值 → input[0] 参与方案 A 的 repair_cfg 验证。 */
    g_opaque = input[0];

    /* 3. 获取 soKey */
    uint8_t soKey[SOKEY_LEN];
    fetch_sokey(env, obj, soKey);

    /* 4. 两个方案都执行，避免 coverage trace 直接观察阶段进度 */
    int okA = verify_scheme_a(flagA, soKey);
    int okB = verify_scheme_b(flagB, soKey);
    int result = (okA & okB) ? 1 : 0;

    secure_bzero(input, sizeof(input));
    secure_bzero(flagA, sizeof(flagA));
    secure_bzero(flagB, sizeof(flagB));
    secure_bzero(soKey, sizeof(soKey));
    return result;
}
