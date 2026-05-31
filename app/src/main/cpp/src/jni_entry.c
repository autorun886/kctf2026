#include <jni.h>
#include <stdint.h>
#include <string.h>
#include "include/kctf.h"

/* ── 硬编码 IV（方案 B）─────────────────────────────────── */
static volatile const uint8_t IV[STATE_LEN] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
};

/* ── 加密后的目标状态（precompute_b.py，Release build，CRC=2ba68be6）── */
static volatile const uint8_t ENC_EXPECTED_STATE[STATE_LEN] = {
    0x39, 0x05, 0x05, 0x44, 0xFE, 0xC6, 0xBC, 0xF6,
    0x20, 0x5B, 0x41, 0x0E, 0xFA, 0x85, 0x24, 0xEB
};

/* ── 第二 IV（唯一性约束，与 IV1 不同）──────────────────── */
static volatile const uint8_t IV2[STATE_LEN] = {
    0xA5,0x5A,0xC3,0x3C,0xF0,0x0F,0x69,0x96,
    0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0
};

/* ── 第二次 SPN 目标状态（converge.py 收敛后填入）────────── */
static volatile const uint8_t ENC_EXPECTED_STATE2[STATE_LEN] = {
    0x01, 0xD8, 0xB7, 0x86, 0xE9, 0xD3, 0x5D, 0x01,
    0xF2, 0x97, 0x9F, 0xA4, 0xE9, 0x87, 0x64, 0x59
};

/* ── 方案 A 目标状态（precompute_a.py，Release build，CRC=2ba68be6）── */
static volatile const uint8_t ENC_EXPECTED_STATE_A[STATE_LEN] = {
    0x5D, 0xEA, 0xE0, 0x84, 0x4B, 0x27, 0x79, 0x1A,
    0xF7, 0x95, 0x11, 0xB8, 0x3C, 0x83, 0xFE, 0x42
};

/* ── JNI 回调获取 soKey ──────────────────────────────────── */
static void fetch_sokey(JNIEnv *env, jobject obj, uint8_t out[SOKEY_LEN]) {
    jclass    clazz = (*env)->GetObjectClass(env, obj);
    jmethodID mid   = (*env)->GetMethodID(env, clazz, "deriveNativeKey", "()[B");
    jbyteArray jarr = (jbyteArray)(*env)->CallObjectMethod(env, obj, mid);
    (*env)->GetByteArrayRegion(env, jarr, 0, SOKEY_LEN, (jbyte *)out);
    (*env)->DeleteLocalRef(env, jarr);
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
    for (int i = 0; i < STATE_LEN; i++)
        expected[i] = ENC_EXPECTED_STATE_A[i] ^ soKey[i];

    volatile uint8_t diff = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff |= final_state[i] ^ expected[i];

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

    uint8_t sboxes[SPN_SBOXES][256];
    for (int i = 0; i < SPN_SBOXES; i++)
        generate_sbox(params.sbox_seeds[i], sboxes[i]);

    /* 第一次 SPN（IV1）*/
    uint8_t state[STATE_LEN];
    memcpy(state, IV, STATE_LEN);
    spn_encrypt(state, &params, sboxes);

    uint8_t expected[STATE_LEN];
    for (int i = 0; i < STATE_LEN; i++)
        expected[i] = ENC_EXPECTED_STATE[i] ^ soKey[i];

    volatile uint8_t diff = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff |= state[i] ^ expected[i];

    /* 第二次 SPN（IV2）：总约束 256 bit > 200 bit，保证唯一性 */
    uint8_t state2[STATE_LEN];
    memcpy(state2, IV2, STATE_LEN);
    spn_encrypt(state2, &params, sboxes);

    uint8_t expected2[STATE_LEN];
    for (int i = 0; i < STATE_LEN; i++)
        expected2[i] = ENC_EXPECTED_STATE2[i] ^ soKey[i];

    volatile uint8_t diff2 = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff2 |= state2[i] ^ expected2[i];

    return (diff == 0 && diff2 == 0) ? 1 : 0;
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

    /* 4. 方案 A（顺序依赖：必须先通过）*/
    if (!verify_scheme_a(flagA, soKey)) return 0;

    /* 5. 方案 B */
    if (!verify_scheme_b(flagB, soKey)) return 0;

    return 1;
}
