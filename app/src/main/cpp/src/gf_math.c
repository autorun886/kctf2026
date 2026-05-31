#include <stdint.h>

/* GF(2^8) 乘法，不可约多项式 x^8+x^4+x^3+x+1 (0x11B) */
static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) r ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return r;
}

/* GF(2^8) 快速幂 */
static inline uint8_t gf_pow(uint8_t base, uint8_t exp) {
    uint8_t result = 1;
    while (exp > 0) {
        if (exp & 1) result = gf_mul(result, base);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    return result;
}
