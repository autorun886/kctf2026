#pragma once
#include <stdint.h>

/* Derive 16-byte XOR key for .rodata constant protection.
 * Uses MBA-Feistel (share_0) + code CRC (share_1).
 * converge.py computes the same key to encrypt at build time. */
void get_const_xor_key(uint8_t key[16]);

/* Decrypt a 16-byte buffer using the const XOR key (modifies in-place). */
void decrypt_const_16(uint8_t *buf);

/* Copy encrypted bytes from src to dst, XOR-decrypting with const key.
 * Key byte at position i is key[i & 0xF]. */
static inline void const_xor_load(uint8_t *dst, const uint8_t *src, int len) {
    uint8_t key[16];
    get_const_xor_key(key);
    for (int i = 0; i < len; i++)
        dst[i] = src[i] ^ key[i & 0xF];
}