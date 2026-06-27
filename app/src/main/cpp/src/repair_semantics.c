#include <stdint.h>
#include "include/kctf.h"
#include "include/const_xor.h"

extern uint8_t  step2_amount;
extern uint32_t step3_param;
extern uint8_t  step3_bits;
extern uint32_t round_constants[32];

/* 8 组 IO 对（step2(step3(KIN[i], step3_param), step2_amount) 验证） */
static const uint32_t KIN[8]  = {
    0x00000001u, 0x12345678u, 0xdeadbeefu, 0xcafebabeu,
    0x8badf00du, 0xfeedfaceu, 0x01234567u, 0x89abcdefu
};
/* volatile 强制编译器从 .rodata 生成 LDR（XOR 加密存储，converge.py 填入） */
static volatile const uint32_t KOUT_ENC[8] = {
    0x0089b100u, 0xf1c20e18u, 0x40686b99u, 0xa60c2c31u,
    0x9639171au, 0xe56a938bu, 0x8e9f4589u, 0xacb1af8bu
};

static inline uint32_t s3_check(uint32_t val, uint32_t param) {
    uint32_t mask = (step3_bits < 32u) ? ((1u << step3_bits) - 1u) : 0xFFFFFFFFu;
    param &= mask;
    return val ^ ((val >> 5) + param) ^ ((val << 4) + (param >> 12));
}

static inline uint32_t s2_check(uint32_t val, uint8_t amt) {
    amt &= 0x1Fu;
    if (amt == 0) return val;
    return (val << amt) | (val >> (32u - amt));
}

/*
 * repair_semantics — 修复 step2 移位量和 step3 参数。
 *
 * 蜜罐 D（无分支）：独立 BRK 扫描，有断点时翻转 step2_amount bit0，
 *   使 KIN/KOUT 验证失败 → step2_amount 清零。
 */
void repair_semantics(const uint8_t *flag, uint8_t rc_high4) {
    /* 花指令：永真分支，.word 迷惑反汇编器 */
    { volatile uint32_t _a = g_opaque; volatile uint32_t _b = g_opaque;
    __asm__ volatile(
        "cmp %w0, %w1\n\t"
        "b.eq 1f\n\t"
        ".word 0x0BADC0DE\n\t"
        "1:\n\t"
        :: "r"(_a), "r"(_b) : "cc"
    ); }

    /* 蜜罐 D：独立 BRK 扫描（不共享 spn_round.c 的全局变量） */
    extern char __executable_start;
    uint32_t *code = (uint32_t *)&__executable_start;
    int brk_count = 0;
    for (int i = 0; i < 1024; i++) {
        if ((code[i] & 0xFFE00000u) == 0xD4200000u)
            brk_count++;
    }
    /* 无分支：有断点时 budget_flag=1，翻转 step2_amount bit0 */
    uint8_t budget_flag = (brk_count > 0) ? 1u : 0u;

    step2_amount = (flag[21] & 0x1Fu) ^ budget_flag;
    step3_bits   = 16u + (rc_high4 & 0x0Fu);

    uint32_t raw = ((uint32_t)flag[22])
                 | ((uint32_t)flag[23] << 8)
                 | ((uint32_t)flag[24] << 16);
    uint32_t mask = (step3_bits < 32u) ? ((1u << step3_bits) - 1u) : 0xFFFFFFFFu;
    step3_param = raw & mask;

    /* KIN/KOUT 验证：确认 step2_amount + step3_param + step3_bits 正确 */
    uint8_t cx_key[16];
    get_const_xor_key(cx_key);
    for (int i = 0; i < 8; i++) {
        uint32_t out = s2_check(s3_check(KIN[i], step3_param), step2_amount);
        /* XOR 解密 KOUT 值（volatile 确保从 .rodata 加载，不受 .text CRC 影响） */
        volatile uint32_t kout = KOUT_ENC[i] ^ *(const volatile uint32_t *)&cx_key[(i * 4) & 0xF];
        if (out != kout) {
            step2_amount = 0;  /* 蜜罐：移位量清零，core_compute 结果错误 */
            return;
        }
    }
}
