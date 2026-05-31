#include <stdint.h>
#include "include/kctf.h"

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
    __asm__ volatile(
        "cmp xzr, xzr\n\t"
        "b.eq 1f\n\t"
        ".word 0xBAADF00D\n\t"
        "1:\n\t"
        ::: "cc"
    );
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

    /* 已知对验证：3 字节约束，把有效 seed 从 ~1.6 亿压到 ~1 个 */
    static volatile const uint8_t SBOX_CHECK[3] = {0x03, 0x62, 0x02};  /* converge.py 填入 */
    /* volatile 局部变量强制内存加载，阻止编译器将值编码为 .text 立即数（避免 CRC 振荡） */
    volatile uint8_t sc0 = SBOX_CHECK[0];
    volatile uint8_t sc1 = SBOX_CHECK[1];
    volatile uint8_t sc2 = SBOX_CHECK[2];
    if (sbox_shipped[0] != sc0 ||
        sbox_shipped[1] != sc1 ||
        sbox_shipped[2] != sc2) {
        /* 蜜罐：恢复恒等映射，core_compute 结果错误 */
        for (int i = 0; i < 256; i++) sbox_shipped[i] = (uint8_t)i;
    }
}
