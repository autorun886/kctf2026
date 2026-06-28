#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <time.h>
#include "include/kctf.h"
#include "include/const_xor.h"

extern uint8_t  sbox_shipped[256];
extern uint32_t round_constants[32];
extern uint32_t xtea_delta;

/* const_xor piece 0: CRC32 of KPT (24 bytes LE) — 耦合到 const_xor.c
 * 选手需要识别这里用的是同一组 KPT 做 CRC32 来生成解密密钥的一部分 */
uint32_t cxk_get_piece0(void) {
    static const uint32_t kpt_raw[6] = {
        0x00000001u, 0x00000002u, 0xdeadbeefu, 0xcafebabeu,
        0x12345678u, 0x9abcdef0u
    };
    uint32_t crc = 0xFFFFFFFFu;
    const uint8_t *p = (const uint8_t *)kpt_raw;
    for (int i = 0; i < 24; i++) {
        crc ^= p[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1u));
    }
    return crc ^ 0xFFFFFFFFu;
}

/* 3 组已知明密文对（xtea_check_encrypt 验证 xtea_delta + round_constants） */
static const uint32_t KPT[3][2] = {
    {0x00000001u, 0x00000002u},
    {0xdeadbeefu, 0xcafebabeu},
    {0x12345678u, 0x9abcdef0u}
};
/* volatile 强制编译器从 .rodata 生成 LDR（XOR 加密存储，converge.py 填入） */
static volatile const uint32_t KCT_ENC[3][2] = {
    {0x6777920du, 0x91814c03u},
    {0x72049451u, 0xb9576a2eu},
    {0x24b10981u, 0xfcae6e58u}
};

/* 简化 XTEA 加密（仅依赖 xtea_delta + round_constants，不用 step2/step3） */
static void xtea_check_encrypt(uint32_t v[2]) {
    uint32_t delta_acc = 0;
    for (int r = 0; r < 16; r++) {
        delta_acc += xtea_delta;
        v[0] += (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (delta_acc + round_constants[r * 2]);
        v[1] += (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (delta_acc + round_constants[r * 2 + 1]);
    }
}

/*
 * repair_constants — 修复 XTEA delta 和 32 个轮常量。
 *
 * 蜜罐 B（无分支）：独立时间差检测，异常时多跑 8 轮 LCG，
 *   使 round_constants 错误 → KPT/KCT 验证失败 → 走蜜罐。
 * 蜜罐（KPT/KCT 验证失败）：xtea_delta ^= 1u。
 */
void repair_constants(const uint8_t *flag, uint8_t sbox_first) {
    /* 花指令：永真分支，.word 迷惑反汇编器 */
    { volatile uint32_t _a = g_opaque; volatile uint32_t _b = g_opaque;
    __asm__ volatile(
        "cmp %w0, %w1\n\t"
        "b.eq 1f\n\t"
        ".word 0xDEADC0DE\n\t"
        "1:\n\t"
        :: "r"(_a), "r"(_b) : "cc"
    ); }

    /* 蜜罐 B：独立时间差检测（不共享 key_expand.c 的全局变量） */
    typedef int (*fn_cgt)(clockid_t, struct timespec *);
    fn_cgt p_cgt = (fn_cgt)get_func_by_id(0);  /* clock_gettime */
    struct timespec t1, t2;
    if (p_cgt) { p_cgt(CLOCK_MONOTONIC, &t1); }
    else        { clock_gettime(CLOCK_MONOTONIC, &t1); }
    volatile uint32_t dummy = 0;
    for (int i = 0; i < 1000; i++) dummy += (uint32_t)(i * i);
    if (p_cgt) { p_cgt(CLOCK_MONOTONIC, &t2); }
    else        { clock_gettime(CLOCK_MONOTONIC, &t2); }
    long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L + (t2.tv_nsec - t1.tv_nsec);
    /* 无分支：正常 penalty=0，调试器导致时间膨胀 penalty=8 */
    int penalty = (ns > 200000000L) * 8;

    xtea_delta = *(const uint32_t *)(flag + 13);

    uint32_t lcg = *(const uint32_t *)(flag + 17);
    lcg ^= (uint32_t)sbox_first * 0x01010101u;

    /* 正常 32 轮；异常时多跑 8 轮（seed 被污染，前 32 个值错误） */
    int rc_rounds = 32 + penalty;
    for (int i = 0; i < rc_rounds; i++) {
        lcg = lcg * 1664525u + 1013904223u;
        if (i < 32) round_constants[i] = lcg;
    }

    /* KPT/KCT 验证：确认 xtea_delta + round_constants 正确 */
    uint8_t cx_key[16];
    get_const_xor_key(cx_key);
    for (int i = 0; i < 3; i++) {
        uint32_t v[2] = {KPT[i][0], KPT[i][1]};
        xtea_check_encrypt(v);
        /* XOR 解密 KCT 值（volatile 确保从 .rodata 加载，不受 .text CRC 影响） */
        volatile uint32_t kct0 = KCT_ENC[i][0] ^ *(const volatile uint32_t *)&cx_key[(i * 8) & 0xF];
        volatile uint32_t kct1 = KCT_ENC[i][1] ^ *(const volatile uint32_t *)&cx_key[(i * 8 + 4) & 0xF];
        if (v[0] != kct0 || v[1] != kct1) {
            xtea_delta ^= 1u;  /* 蜜罐：delta 差 1，core_compute 结果错误 */
            return;
        }
    }
}
