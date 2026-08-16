#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <dirent.h>
#include "include/kctf.h"
#include "include/const_xor.h"

/* ── 蜜罐 B 全局变量（伪装为缓存策略）────────────────── */
static volatile uint32_t g_cache_policy = 0x03;  /* 正常值 = 3 */
volatile uint32_t g_java_archive_profile_delta = 0xD17F00D5u;

/* ── 时间差检测（检测点 B）──────────────────────────── */
static void adapt_cache_strategy(void) {
    typedef int (*fn_cgt)(clockid_t, struct timespec *);
    fn_cgt p_cgt = (fn_cgt)get_func_by_id(0);  /* clock_gettime */
    if (!p_cgt) return;
    struct timespec t1, t2;
    p_cgt(CLOCK_MONOTONIC, &t1);
    volatile uint32_t x = 0;
    for (int i = 0; i < 1000; i++) x += (uint32_t)(i * i);
    p_cgt(CLOCK_MONOTONIC, &t2);
    long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L
            + (t2.tv_nsec - t1.tv_nsec);
    g_cache_policy = (ns > 200000000L) ? 0x07u : 0x03u;
}

/* ── ARX 辅助宏 ──────────────────────────────────────── */
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/* ── 多阶段 MBA primitives：矩阵层 + 非线性 identity 包装 ── */
static uint8_t mba_gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(0u - (b & 1u));
        r ^= a & mask;
        uint8_t hi = a >> 7;
        a <<= 1;
        a ^= (uint8_t)(0x1Bu & (uint8_t)(0u - hi));
        b >>= 1;
    }
    return r;
}

static uint32_t mba_mds32(uint32_t x) {
    uint8_t a0 = (uint8_t)x, a1 = (uint8_t)(x >> 8);
    uint8_t a2 = (uint8_t)(x >> 16), a3 = (uint8_t)(x >> 24);
    uint8_t b0 = mba_gf_mul(a0, 2) ^ mba_gf_mul(a1, 3) ^ a2 ^ a3;
    uint8_t b1 = a0 ^ mba_gf_mul(a1, 2) ^ mba_gf_mul(a2, 3) ^ a3;
    uint8_t b2 = a0 ^ a1 ^ mba_gf_mul(a2, 2) ^ mba_gf_mul(a3, 3);
    uint8_t b3 = mba_gf_mul(a0, 3) ^ a1 ^ a2 ^ mba_gf_mul(a3, 2);
    return (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
}

static uint32_t mba_inv_mds32(uint32_t x) {
    uint8_t a0 = (uint8_t)x, a1 = (uint8_t)(x >> 8);
    uint8_t a2 = (uint8_t)(x >> 16), a3 = (uint8_t)(x >> 24);
    uint8_t b0 = mba_gf_mul(a0, 0x0e) ^ mba_gf_mul(a1, 0x0b) ^ mba_gf_mul(a2, 0x0d) ^ mba_gf_mul(a3, 0x09);
    uint8_t b1 = mba_gf_mul(a0, 0x09) ^ mba_gf_mul(a1, 0x0e) ^ mba_gf_mul(a2, 0x0b) ^ mba_gf_mul(a3, 0x0d);
    uint8_t b2 = mba_gf_mul(a0, 0x0d) ^ mba_gf_mul(a1, 0x09) ^ mba_gf_mul(a2, 0x0e) ^ mba_gf_mul(a3, 0x0b);
    uint8_t b3 = mba_gf_mul(a0, 0x0b) ^ mba_gf_mul(a1, 0x0d) ^ mba_gf_mul(a2, 0x09) ^ mba_gf_mul(a3, 0x0e);
    return (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
}

static uint32_t mba_fbox32(uint32_t x, uint32_t k) {
    x ^= k;
    x *= 0x45D9F3Bu;
    x ^= x >> 16;
    x *= 0x119DE1F3u;
    x ^= x >> 15;
    return x;
}

static uint32_t mba_feistel32(uint32_t x, uint32_t k) {
    uint16_t l = (uint16_t)x, r = (uint16_t)(x >> 16);
    l ^= (uint16_t)mba_fbox32(r, k);
    r ^= (uint16_t)mba_fbox32(l, k ^ 0x9E37u);
    return (uint32_t)l | ((uint32_t)r << 16);
}

static uint32_t mba_inv_feistel32(uint32_t x, uint32_t k) {
    uint16_t l = (uint16_t)x, r = (uint16_t)(x >> 16);
    r ^= (uint16_t)mba_fbox32(l, k ^ 0x9E37u);
    l ^= (uint16_t)mba_fbox32(r, k);
    return (uint32_t)l | ((uint32_t)r << 16);
}

__attribute__((noinline))
static uint64_t mba_add64(uint64_t a, uint64_t b, uint64_t salt) {
    uint64_t s = a, c = b;
    for (int i = 0; i < 64; i++) {
        uint64_t ns = s ^ c;
        c = (s & c) << 1;
        s = ns;
    }
    uint32_t lo = (uint32_t)s;
    uint32_t hi = (uint32_t)(s >> 32);
    lo = mba_inv_feistel32(mba_feistel32(lo, (uint32_t)salt), (uint32_t)salt);
    hi = mba_inv_feistel32(mba_feistel32(hi, (uint32_t)(salt >> 32)), (uint32_t)(salt >> 32));
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

__attribute__((noinline))
static uint64_t mba_xor64(uint64_t a, uint64_t b, uint64_t salt) {
    uint32_t ma0 = mba_fbox32((uint32_t)salt, 0xA0761D64u);
    uint32_t mb0 = mba_fbox32((uint32_t)(salt >> 32), 0xE7037ED1u);
    uint32_t ma1 = mba_fbox32((uint32_t)(salt >> 17), 0x8EBC6AF1u);
    uint32_t mb1 = mba_fbox32((uint32_t)(salt >> 7), 0x589965CCu);

    uint32_t lo = mba_inv_mds32(mba_mds32(((uint32_t)a) ^ ma0) ^ mba_mds32(((uint32_t)b) ^ mb0)) ^ ma0 ^ mb0;
    uint32_t hi = mba_inv_mds32(mba_mds32(((uint32_t)(a >> 32)) ^ ma1) ^ mba_mds32(((uint32_t)(b >> 32)) ^ mb1)) ^ ma1 ^ mb1;
    lo = mba_inv_feistel32(mba_feistel32(lo, ma0 ^ mb0), ma0 ^ mb0);
    hi = mba_inv_feistel32(mba_feistel32(hi, ma1 ^ mb1), ma1 ^ mb1);
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

static uint32_t hook_signature(void *fn) {
    if (!fn) return 0;
    const volatile uint32_t *code = (const volatile uint32_t *)fn;
    uint32_t sig = 0;
    uint32_t prev_ldr = 0;
    for (int i = 0; i < 6; i++) {
        uint32_t insn = code[i];
        if ((insn & 0x7C000000u) == 0x14000000u)
            sig ^= 0x01010101u << (i & 3);
        if ((insn & 0xFFE00000u) == 0xD4200000u)
            sig ^= 0x3D5A7C11u ^ (uint32_t)i;
        if (prev_ldr) {
            uint32_t op = insn & 0xFFFFFC1Fu;
            if (op == 0xD61F0000u || op == 0xD63F0000u)
                sig ^= 0x6B2D41E9u + (uint32_t)i;
        }
        prev_ldr = ((insn & 0xFF000000u) == 0x58000000u);
    }
    return sig;
}

static uint8_t java_profile_padding_byte(void) {
    uint32_t d = g_java_archive_profile_delta;
    uint32_t nz = (d | (0u - d)) >> 31;
    uint32_t mask = 0u - nz;
    uint32_t p = d ^ (d >> 8) ^ (d >> 16) ^ (d >> 24) ^ 0xA5u;
    return (uint8_t)(0x5Au ^ (p & mask & 0xFFu));
}

__attribute__((noinline))
static void kx_decode_string(char *out, size_t out_cap,
                             const volatile uint8_t *enc, size_t len,
                             uint8_t seed) {
    if (!out || out_cap == 0) return;
    if (len >= out_cap)
        len = out_cap - 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = enc[i];
        uint8_t mask = (uint8_t)((seed + (uint8_t)(i * 0x3Du)) ^ (uint8_t)(i >> 1));
        out[i] = (char)(c ^ mask);
    }
    out[len] = 0;
}

static uint32_t frida_thread_signature(void) {
    static volatile const uint8_t enc_task_dir[] = {
        0x64, 0xF8, 0xB6, 0x6C, 0x5E, 0x51, 0xC9, 0x90,
        0x5B, 0x12, 0x87, 0x9B, 0x40, 0x11, 0xCD
    };
    static volatile const uint8_t enc_task_fmt[] = {
        0x18, 0x04, 0xC2, 0x80, 0x4A, 0x45, 0xD5, 0x84,
        0x77, 0x3E, 0xB3, 0xA7, 0x74, 0x25, 0xE1, 0xE2,
        0x2A, 0x3F, 0xA7, 0xD4, 0x9E, 0x5F, 0x13
    };
    static volatile const uint8_t enc_needles[4][11] = {
        { 0xEA, 0xBF, 0x6B, 0x68, 0xE9, 0xCF, 0xD5, 0x57, 0x1E, 0xD9, 0x9A },
        { 0xD6, 0x83, 0x4B, 0x00, 0xC9 },
        { 0x08, 0xC8, 0x8A, 0x52, 0x12 },
        { 0xAC, 0x75, 0x2C, 0xE4, 0xDD }
    };
    static const uint8_t needle_len[] = { 11, 5, 5, 5 };
    static const uint8_t needle_seed[] = { 0x8Du, 0xB1u, 0x6Fu, 0xCAu };

    char task_dir[32];
    char task_fmt[32];
    char needle[4][12];
    kx_decode_string(task_dir, sizeof(task_dir), enc_task_dir, sizeof(enc_task_dir), 0x4Bu);
    kx_decode_string(task_fmt, sizeof(task_fmt), enc_task_fmt, sizeof(enc_task_fmt), 0x37u);
    for (int i = 0; i < 4; i++)
        kx_decode_string(needle[i], sizeof(needle[i]), enc_needles[i], needle_len[i], needle_seed[i]);

    DIR *dir = opendir(task_dir);
    uint32_t sig = 0;
    if (!dir)
        goto out;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        if (name[0] == '.') continue;
        char path[96];
        int n = snprintf(path, sizeof(path), task_fmt, name);
        if (n <= 0 || n >= (int)sizeof(path)) continue;
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char comm[64];
        size_t got = fread(comm, 1, sizeof(comm) - 1, fp);
        fclose(fp);
        comm[got] = 0;
        if (strstr(comm, needle[0])) sig ^= 0xF17DA901u;
        if (strstr(comm, needle[1])) sig ^= 0x6D4A11B5u;
        if (strstr(comm, needle[2])) sig ^= 0xDB97531Fu;
        if (strstr(comm, needle[3])) sig ^= 0xA11CEBADu;
    }
out:
    if (dir) closedir(dir);
    secure_bzero(task_dir, sizeof(task_dir));
    secure_bzero(task_fmt, sizeof(task_fmt));
    secure_bzero(needle, sizeof(needle));
    return sig;
}

/*
 * expand_key_material — 伪装名：chacha20_quarter_round
 * 将 25 字节 flag 通过 ARX 扩展为 out_len 字节密钥材料。
 * 蜜罐 B（无分支）：调试器导致时间膨胀 → rounds 从 12 降为 8。
 */
void expand_key_material(const uint8_t *input, uint8_t *out, int out_len) {
    /* 花指令：cmp xzr,xzr 永真，b.ne 永不跳，.word 迷惑反汇编器 */
    { volatile uint32_t _a = g_opaque; volatile uint32_t _b = g_opaque;
    __asm__ volatile(
        "cmp %w0, %w1\n\t"
        "b.eq 1f\n\t"
        ".word 0xDEADBEEF\n\t"
        "1:\n\t"
        :: "r"(_a), "r"(_b) : "cc"
    ); }
    KCTF_HONEY_BR_BAIT_CSEL(0xB401u,
        ((uint32_t)input[0] | ((uint32_t)input[7] << 8) |
         ((uint32_t)input[16] << 16) | ((uint32_t)input[24] << 24)) ^ (uint32_t)out_len);
    KCTF_REAL_BR_FALSE_BAIT(0xE401u,
        ((uint32_t)input[3] | ((uint32_t)input[11] << 8) |
         ((uint32_t)input[19] << 16) | ((uint32_t)out_len << 24)),
        key_schedule);

    adapt_cache_strategy();

    uint64_t s[4];
    memcpy(s, input, 25);
    memset((uint8_t *)s + 25, java_profile_padding_byte(), 7);  /* padding */

    /* 无分支蜜罐：正常 policy=3 → penalty=0 → rounds=12
     *             异常 policy=7 → penalty=4 → rounds=8   */
    int penalty = (g_cache_policy != 0x03u) * 4;
    int rounds  = 12 - penalty;

    for (int r = 0; r < rounds; r++) {
        uint64_t salt = 0x9E3779B97F4A7C15ULL ^ (uint64_t)r ^ s[3];
        s[0] = mba_xor64(mba_add64(ROR64(s[0], 8), s[1], salt), (uint64_t)r, salt);
        s[1] = mba_xor64(ROL64(s[1], 3), s[0], salt ^ 0xD1B54A32D192ED03ULL);
        s[2] = mba_xor64(mba_add64(ROR64(s[2], 8), s[3], salt ^ s[0]), (uint64_t)(r + 4), salt ^ 0x94D049BB133111EBULL);
        s[3] = mba_xor64(ROL64(s[3], 3), s[2], salt ^ 0x2545F4914F6CDD1DULL);
        s[0] = mba_xor64(s[0], s[3], salt ^ s[1]);
        s[2] = mba_xor64(s[2], s[1], salt ^ s[3]);
    }

    /* Squeeze：每次输出 32 字节，额外置换后继续 */
    int pos = 0;
    while (pos < out_len) {
        int chunk = (out_len - pos < 32) ? (out_len - pos) : 32;
        memcpy(out + pos, s, (size_t)chunk);
        pos += chunk;
        s[0] = mba_add64(s[0], s[2], s[1] ^ 0xA0761D6478BD642FULL);
        s[1] = mba_xor64(s[1], s[3], s[0] ^ 0xE7037ED1A0B428DBULL);
        s[2]  = ROL64(s[2], 17);
        s[3]  = ROR64(s[3], 11);
    }
}

/* soKey 双向验证常量（XOR 加密存储，converge.py 填入） */
static volatile const uint32_t EXPECTED_SOKEY_CHECK_ENC = 0xf85f0ebau;

/*
 * key_schedule — 从 flag + soKey 派生 runtime_params。
 * soKey 双向验证（无分支）：错误 soKey → delta 被 0xDEADBEEF 污染。
 */
void key_schedule(const uint8_t *flag, const uint8_t *so_key,
                  struct runtime_params *params) {
    KCTF_HONEY_BR_BAIT(0xB502u,
        ((uint32_t)flag[0] | ((uint32_t)flag[12] << 8) |
         ((uint32_t)so_key[0] << 16) | ((uint32_t)so_key[15] << 24)));
    KCTF_REAL_BR_FALSE_BAIT_CSEL(0xE502u,
        ((uint32_t)flag[8] | ((uint32_t)flag[16] << 8) |
         ((uint32_t)so_key[4] << 16) | ((uint32_t)so_key[12] << 24)),
        spn_encrypt);

    uint8_t material[128];

    /* 1. ARX 扩展 96 字节 */
    expand_key_material(flag, material, 96);

    /* 2. soKey 混入 material[96:112] */
    for (int i = 0; i < 16; i++)
        material[96 + i] = material[i] ^ so_key[i];

    /* 3. IPC/attestation share 混入 material[112:128] */
    uint8_t ipc[16];
    get_ipc_material(ipc);
    for (int i = 0; i < 16; i++)
        material[112 + i] = material[32 + i] ^ ipc[i];

    /* 4. 派生 round_keys[16]：material[0:64] 与 IPC share 交叉混合 */
    for (int i = 0; i < 16; i++) {
        uint32_t ipc_word = *(uint32_t *)(material + 112 + ((i & 3) * 4));
        params->round_keys[i] = (uint32_t)mba_xor64(*(uint32_t *)(material + i * 4), ipc_word, (uint64_t)i * 0xD6E8FEB86659FD93ULL);
    }

    /* 5. 派生 configs[16]：material[64:80] 每字节拆 4 个 2-bit 字段 */
    for (int i = 0; i < 16; i++) {
        uint8_t b = material[64 + i];
        params->configs[i].sbox_selector  = (b >> 0) & 0x03u;
        params->configs[i].shift_pattern  = (b >> 2) & 0x03u;
        params->configs[i].mix_matrix_idx = (b >> 4) & 0x03u;
        params->configs[i].nonlinear_mode = (b >> 6) & 0x03u;
    }

    /* 6. 派生 sbox_seeds[4]：material[80:96] */
    for (int i = 0; i < 4; i++)
        params->sbox_seeds[i] = *(uint32_t *)(material + 80 + i * 4);

    /* 7. 派生 delta：material[96:100]（已混入 soKey） */
    params->delta = (uint32_t)mba_xor64(*(uint32_t *)(material + 96), *(uint32_t *)(material + 112), 0xC2B2AE3D27D4EB4FULL);

    /* 8. soKey 双向验证（无分支算术污染）
     *    正确 soKey → diff=0 → poison=0 → delta 不变
     *    错误 soKey → diff≠0 → poison=0xDEADBEEF → delta 被污染 */
    uint8_t cx_key[16];
    get_const_xor_key(cx_key);
    uint32_t bait_z = kctf_bait_zero_mask(0x6502u,
        *(const uint32_t *)so_key ^ *(const uint32_t *)(material + 96));
    uint32_t sokey_check_dec = EXPECTED_SOKEY_CHECK_ENC ^ *(const uint32_t *)cx_key ^ bait_z;
    uint32_t check  = (uint32_t)mba_xor64(params->round_keys[15], *(const uint32_t *)(so_key + 12), 0x165667B19E3779F9ULL);
    uint32_t diff   = (uint32_t)mba_xor64(check, sokey_check_dec, 0x85EBCA77C2B2AE63ULL);
    uint32_t poison = ((diff | (~diff + 1u)) >> 31) * 0xDEADBEEFu;
    params->delta = (uint32_t)mba_xor64(params->delta, poison, 0x27D4EB2F165667C5ULL);

    /* 9. 蜜罐 F：Inline Hook 完整性检测（伪装为"内存池校验"）
     *    检测关键 libc 函数入口是否被 Frida/Xposed 篡改。
     *    每个函数命中后写入不同错误状态，避免统一 poison 可被抵消。 */
    {
        static const uint8_t ids[5] = {0, 4, 5, 7, 8};
        static const uint32_t poison32[5] = {
            0xC10C6E7Du, 0x0F3A0D55u, 0x51EAD5A7u, 0xA7C0F11Du, 0x4D4D4150u
        };
        for (int t = 0; t < 5; t++) {
            uint32_t sig = hook_signature(get_func_by_id(ids[t]));
            uint32_t mask = 0u - (uint32_t)(sig != 0u);
            uint32_t p = (poison32[t] ^ sig ^ (uint32_t)(t * 0x45D9F3Bu)) & mask;
            params->delta = (uint32_t)mba_xor64(params->delta, p,
                                                0x9E3779B185EBCA87ULL ^ (uint64_t)t);
            params->round_keys[(t * 5 + 3) & 0x0F] =
                (uint32_t)mba_xor64(params->round_keys[(t * 5 + 3) & 0x0F],
                                    (uint32_t)((p << (t + 1)) | (p >> (31 - t))),
                                    0xD6E8FEB86659FD93ULL ^ (uint64_t)poison32[t]);
            params->sbox_seeds[t & 3] =
                (uint32_t)mba_xor64(params->sbox_seeds[t & 3],
                                    (uint32_t)((p >> (t + 3)) | (p << (29 - t))),
                                    0xA0761D6478BD642FULL ^ (uint64_t)t);
        }
        {
            uint32_t sig = frida_thread_signature();
            uint32_t mask = 0u - (uint32_t)(sig != 0u);
            uint32_t p = (0xF17DA7A5u ^ sig) & mask;
            uint32_t p_rk = (p ^ 0x9E3779B9u) & mask;
            uint32_t p_sb = (p ^ 0x85EBCA77u) & mask;
            params->delta = (uint32_t)mba_xor64(params->delta, p, 0x510E527FA54FF53AULL);
            params->round_keys[11] = (uint32_t)mba_xor64(params->round_keys[11],
                                                         p_rk,
                                                         0x1F83D9AB5BE0CD19ULL);
            params->sbox_seeds[2] = (uint32_t)mba_xor64(params->sbox_seeds[2],
                                                        p_sb,
                                                        0xC2B2AE3527D4EB2FULL);
        }
    }
}
