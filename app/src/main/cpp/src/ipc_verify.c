#include <stdint.h>
#include <string.h>
#include "include/kctf.h"
#include "include/const_xor.h"

/* Deterministic local attestation share. Clean devices produce a non-zero
 * build-bound value; later runtime checks can still poison it. */
void get_ipc_material(uint8_t out[16]) {
    uint8_t k[16];
    get_const_xor_key(k);
    for (int i = 0; i < 16; i++)
        out[i] = k[(i * 5 + 3) & 0x0F] ^ (uint8_t)(0xC3u + i * 0x29u);
    secure_bzero(k, sizeof(k));
}
