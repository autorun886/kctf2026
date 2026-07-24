#include <stdint.h>
#include "include/kctf.h"
#include "include/const_xor.h"

extern uint8_t  sbox_shipped[256];
extern uint32_t dispatch_table[4];  /* repair_cfg 填入 */

/*
 * repair_sbox — 用 xorshift32 PRNG 还原 sbox_shipped。
 *
 * seed = flag[9:13]
 * 起始偏移 = dispatch_table[0] & 0xFF（非线性耦合）
 * 正确结果必须是双射（256 个不同值各出现恰好一次）。
 */
void repair_sbox(const uint8_t *flag, uint8_t cfg_dependency) {
    /* 花指令：永真分支，.word 迷惑反汇编器 */
    { volatile uint32_t _a = g_opaque; volatile uint32_t _b = g_opaque;
    __asm__ volatile(
        "cmp %w0, %w1\n\t"
        "b.eq 1f\n\t"
        ".word 0xBAADF00D\n\t"
        "1:\n\t"
        :: "r"(_a), "r"(_b) : "cc"
    ); }
    uint32_t seed = *(const uint32_t *)(flag + 9);
    (void)cfg_dependency;  /* 由调用方传入 dispatch_table[0]&0xFF */

    uint32_t xs = seed;
    uint8_t  key_stream[256];
    for (int i = 0; i < 256; i++) {
        xs ^= xs << 13;
        xs ^= xs >> 17;
        xs ^= xs << 5;
        key_stream[i] = (uint8_t)xs;
    }

    /* XOR 还原，起始偏移由 cfg_dependency 决定 */
    uint8_t offset = (uint8_t)(dispatch_table[0] & 0xFFu);
    for (int i = 0; i < 256; i++)
        sbox_shipped[(i + offset) & 0xFFu] ^= key_stream[i];

    /* 已知对验证：3 字节约束（XOR 加密，converge.py 填入） */
    static volatile const uint8_t SBOX_CHECK_ENC[3] = {0x27, 0x02, 0x32};
    /* XOR 解密后比较（volatile 强制 .rodata LDR 加载，避免 .text CRC 振荡） */
    uint8_t cx_key[16];
    get_const_xor_key(cx_key);
    volatile uint8_t sc0 = SBOX_CHECK_ENC[0] ^ cx_key[0];
    volatile uint8_t sc1 = SBOX_CHECK_ENC[1] ^ cx_key[1];
    volatile uint8_t sc2 = SBOX_CHECK_ENC[2] ^ cx_key[2];
    if (sbox_shipped[0] != sc0 ||
        sbox_shipped[1] != sc1 ||
        sbox_shipped[2] != sc2) {
        /* 蜜罐：恢复恒等映射，core_compute 结果错误 */
        for (int i = 0; i < 256; i++) sbox_shipped[i] = (uint8_t)i;
    }
}
