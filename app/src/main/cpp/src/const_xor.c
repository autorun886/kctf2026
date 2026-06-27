/*
 * const_xor.c — XOR key derivation for .rodata constant protection
 * Disabled for compatibility: returns zero key
 */
#include <stdint.h>
#include <string.h>
#include "include/const_xor.h"

__attribute__((noinline))
void get_const_xor_key(uint8_t key[16]) {
    memset(key, 0, 16);
}

void decrypt_const_16(uint8_t *buf) {
    /* No-op when key is zero */
    (void)buf;
}
