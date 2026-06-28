/*
 * const_xor.c — XOR key derivation for .rodata constant protection.
 *
 * Key = LCG_expand(piece0 ^ piece1 ^ piece2)
 *
 * 耦合 3 个模块的固定常量：
 *   piece0: CRC32(KPT)               — repair_constants.c
 *   piece1: IV_A[0] ^ (IV_A[2] ror 13) — core_compute.c
 *   piece2: LE_u32(IV[0:4]) ^ LE_u32(IV2[0:4]) — jni_entry.c
 *
 * 使用与 round_constants 同一 LCG（mul=1664525, inc=1013904223）展开 16 字节。
 * 选手逆向时需要：
 *   1. 找到 get_const_xor_key 并跟进 3 个 cxk_get_piece* 调用
 *   2. 识别各片段的来源（KPT/IV_A/IV+IV2）
 *   3. 认出 LCG 与 repair_constants 的 round_constants 生成同源
 */
#include <stdint.h>
#include <string.h>
#include "include/const_xor.h"

/* 3 个片段函数，分布在不同 .c 文件中 */
extern uint32_t cxk_get_piece0(void);  /* repair_constants.c */
extern uint32_t cxk_get_piece1(void);  /* core_compute.c */
extern uint32_t cxk_get_piece2(void);  /* jni_entry.c */

__attribute__((noinline))
void get_const_xor_key(uint8_t key[16]) {
    uint32_t seed = cxk_get_piece0() ^ cxk_get_piece1() ^ cxk_get_piece2();
    uint32_t s = seed;
    for (int i = 0; i < 4; i++) {
        s = s * 1664525u + 1013904223u;
        memcpy(key + i * 4, &s, 4);
    }
}

void decrypt_const_16(uint8_t *buf) {
    uint8_t key[16];
    get_const_xor_key(key);
    for (int i = 0; i < 16; i++)
        buf[i] ^= key[i];
}
