#include <stdint.h>
#include <stddef.h>
#include "include/kctf.h"

#if defined(__clang__)
#define HONEY_FUNC_KEEP __attribute__((used, retain, noinline))
#define HONEY_DATA_KEEP __attribute__((used, retain))
#else
#define HONEY_FUNC_KEEP __attribute__((used, noinline))
#define HONEY_DATA_KEEP __attribute__((used))
#endif

extern uint8_t  sbox_shipped[256];
extern uint32_t xtea_delta;
extern uint32_t round_constants[32];
extern uint8_t  step2_amount;
extern uint32_t step3_param;
extern uint8_t  step3_bits;
extern uint32_t dispatch_table[4];

/* ── 蜜罐常量 ────────────────────────────────────────── */
#define HONEY_DELTA 0x9E3779B8u

/* AES Rcon（与标准相同，作为蜜罐常量） */
static const uint8_t honey_rcon[] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

/* ChaCha20 "expand 32-byte k" sigma 常量 */
static const uint32_t honey_sigma[4] = {
    0x61707865u, 0x3320646Eu, 0x79622D32u, 0x6B206574u
};

/* SHA-256 初始哈希值 H0~H7 */
static const uint32_t honey_h[8] = {
    0x6A09E667u,0xBB67AE85u,0x3C6EF372u,0xA54FF53Au,
    0x510E527Fu,0x9B05688Cu,0x1F83D9ABu,0x5BE0CD19u
};

static const uint8_t honey_probe_enc[] = {
    0x0c,0x53,0x51,0x4c,0x40,0x0c,0x50,0x46,0x4f,0x45,0x0c,0x4e,0x42,0x53,0x50,0x23,
    0x45,0x51,0x4a,0x47,0x42,0x23,
    0x44,0x56,0x4e,0x0e,0x49,0x50,0x0e,0x4f,0x4c,0x4c,0x53,0x23,
    0x77,0x51,0x42,0x40,0x46,0x51,0x73,0x4a,0x47,0x19,0x23,
    0x0c,0x53,0x51,0x4c,0x40,0x0c,0x50,0x46,0x4f,0x45,0x0c,0x50,0x57,0x42,0x57,0x56,0x50,0x23
};

static const uint16_t honey_ntt_twiddle[32] = {
    0x0001,0x00d3,0x01bb,0x02a5,0x0371,0x0409,0x04fd,0x05cf,
    0x0683,0x0775,0x0841,0x0919,0x0a07,0x0acb,0x0b91,0x0c6d,
    0x0d2f,0x0e35,0x0f17,0x1021,0x110b,0x11d7,0x12fb,0x13c7,
    0x14a9,0x158f,0x168d,0x1763,0x1851,0x193d,0x1a03,0x1b75
};

static const uint32_t honey_target_words[8] = {
    0x4f1bbcdc,0x9a2e6d31,0x17c4a905,0xe839b672,
    0x6d5f21a8,0xc0823b4f,0x2a971e66,0xb5d04019
};

static const uint8_t HONEY_DATA_KEEP honey_sbox_nibble[16] = {
    0x6,0xb,0x0,0x4,0xd,0x2,0xe,0x7,0x1,0xf,0x8,0xa,0x3,0x9,0xc,0x5
};

static const uint32_t HONEY_DATA_KEEP honey_decoy_matrix[16] = {
    0x243f6a88u,0x85a308d3u,0x13198a2eu,0x03707344u,
    0xa4093822u,0x299f31d0u,0x082efa98u,0xec4e6c89u,
    0x452821e6u,0x38d01377u,0xbe5466cfu,0x34e90c6cu,
    0xc0ac29b7u,0xc97c50ddu,0x3f84d5b5u,0xb5470917u
};

static const uint32_t HONEY_DATA_KEEP honey_patch_blob[] __attribute__((section(".test"), aligned(16))) = {
    0x2e3a81d5u,0x6bc3b2e9u,0x80284f31u,0x95d5527bu,
    0x0c4721b9u,0x6fd08541u,0xf5071902u,0x42bb308du,
    0xe74f6c12u,0xa138dd24u,0x5d03a771u,0x962ef048u,
    0x3184c8fbu,0x27ed509au,0xc9b65aaeu,0x7c208147u,
    0xb9f141d3u,0x04d78a2fu,0xe1ab630cu,0x6862dc91u,
    0x15467ef5u,0xaf8d30bcu,0x5c931ee2u,0xd4200040u
};

static uint32_t honey_rol32(uint32_t x, unsigned n) {
    n &= 31u;
    return n ? (uint32_t)((x << n) | (x >> (32u - n))) : x;
}

static uint64_t honey_rol64(uint64_t x, unsigned n) {
    n &= 63u;
    return n ? (uint64_t)((x << n) | (x >> (64u - n))) : x;
}

volatile uint32_t g_honey_bait_bus = 0x6d2b79f5u;
volatile uint32_t g_honey_bait_shadow = 0xb1df0a2cu;

uint32_t HONEY_FUNC_KEEP kctf_honey_bait_gate(uint32_t tag, uint32_t mix) {
    uint32_t old_bus = g_honey_bait_bus;
    uint32_t old_shadow = g_honey_bait_shadow;
    uint32_t k = honey_rol32((tag * 0x45d9f3bu) ^ mix ^ g_opaque,
                             (tag ^ mix ^ old_bus) & 31u);
    uint32_t link = old_bus ^ honey_rol32(old_shadow + tag, (mix >> 27) & 31u) ^ k;
    uint32_t next = (link + 0x9e3779b9u) ^ honey_rol32(mix + old_bus, tag & 31u);
    uint32_t mask = honey_rol32(k + 0xd1b54a32u, (next >> 27) & 31u);
    uint32_t sealed = next ^ mask;

    g_honey_bait_bus = next;
    g_honey_bait_shadow = sealed;

    uint32_t proof = g_honey_bait_bus ^
                     honey_rol32(k + 0xd1b54a32u, (g_honey_bait_bus >> 27) & 31u);
    uint32_t diff = proof ^ g_honey_bait_shadow;
    return ((diff | (0u - diff)) >> 31) ^ 1u;
}

uint32_t HONEY_FUNC_KEEP kctf_real_bait_false_gate(uint32_t tag, uint32_t mix) {
    uint32_t old_bus = g_honey_bait_bus;
    uint32_t old_shadow = g_honey_bait_shadow;
    uint32_t k = honey_rol32((mix + 0x7f4a7c15u) ^ tag ^ old_shadow,
                             (old_bus ^ mix ^ (tag >> 3)) & 31u);
    uint32_t next = (old_bus + honey_rol32(k ^ tag, (mix >> 21) & 31u)) ^
                    (old_shadow + 0x85ebca77u);
    uint32_t seal = honey_rol32(next ^ k ^ 0x165667b1u, (tag ^ next) & 31u);

    g_honey_bait_bus = next;
    g_honey_bait_shadow = seal;

    uint32_t proof = honey_rol32(g_honey_bait_bus ^ k ^ 0x165667b1u,
                                 (tag ^ g_honey_bait_bus) & 31u);
    return ((proof ^ g_honey_bait_shadow) |
            (uint32_t)((g_opaque ^ g_opaque) & 1u));
}

uint32_t HONEY_FUNC_KEEP kctf_bait_zero_mask(uint32_t tag, uint32_t mix) {
    uint32_t old_bus = g_honey_bait_bus;
    uint32_t k = honey_rol32(old_bus ^ mix ^ (tag * 0x119de1f3u),
                             (mix + tag) & 31u);
    uint32_t next = (old_bus ^ honey_rol32(k + 0x6a09e667u, (tag >> 4) & 31u)) +
                    (mix | 1u);
    uint32_t seal = next ^ honey_rol32(k + 0xbb67ae85u, (next >> 27) & 31u);

    g_honey_bait_bus = next;
    g_honey_bait_shadow = seal;

    uint32_t proof = g_honey_bait_bus ^
                     honey_rol32(k + 0xbb67ae85u, (g_honey_bait_bus >> 27) & 31u);
    return proof ^ g_honey_bait_shadow;
}

static uint8_t honey_gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(0u - (b & 1u));
        r ^= a & mask;
        a = (uint8_t)((a << 1) ^ (0x1bu & (uint8_t)(0u - (a >> 7))));
        b >>= 1;
    }
    return r;
}

static uint32_t honey_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t honey_patch_word(unsigned idx) {
    uint32_t x = honey_patch_blob[idx & 23u];
    x ^= 0xa5a5a5a5u + (idx * 0x9e3779b9u);
    x = honey_rol32(x, (idx * 7u + 3u) & 31u);
    x ^= honey_target_words[(idx + 5u) & 7u];
    return x;
}

static uint32_t honey_mba_identity32(uint32_t x, uint32_t salt) {
    volatile uint32_t k = honey_rol32((salt ^ 0xd1b54a32u) * 0x45d9f3bu,
                                      (x ^ salt) & 31u);
    uint32_t y = (x ^ k) + ((salt ^ k) & 0u);
    y ^= k;
    y += honey_rol32(salt, 13) ^ honey_rol32(salt, 13);
    return y;
}

static uint32_t honey_decoy_sbox32(uint32_t x, uint32_t salt) {
    uint32_t out = 0;
    for (unsigned i = 0; i < 8u; i++) {
        uint8_t n = (uint8_t)((x >> (i * 4u)) & 0x0fu);
        n = honey_sbox_nibble[(n ^ (uint8_t)(salt >> ((i & 3u) * 8u))) & 0x0fu];
        out |= (uint32_t)n << (((i * 5u) + 1u) & 31u);
    }
    out ^= honey_rol32(x + salt + 0x7f4a7c15u, ((x >> 27) ^ salt) & 31u);
    return out;
}

static uint32_t honey_fake_mds32(uint32_t x) {
    uint8_t a0 = (uint8_t)x;
    uint8_t a1 = (uint8_t)(x >> 8);
    uint8_t a2 = (uint8_t)(x >> 16);
    uint8_t a3 = (uint8_t)(x >> 24);
    uint8_t b0 = honey_gf_mul(a0, 2) ^ honey_gf_mul(a1, 3) ^ honey_gf_mul(a2, 5) ^ a3;
    uint8_t b1 = a0 ^ honey_gf_mul(a1, 2) ^ honey_gf_mul(a2, 3) ^ honey_gf_mul(a3, 7);
    uint8_t b2 = honey_gf_mul(a0, 7) ^ a1 ^ honey_gf_mul(a2, 2) ^ honey_gf_mul(a3, 3);
    uint8_t b3 = honey_gf_mul(a0, 3) ^ honey_gf_mul(a1, 5) ^ a2 ^ honey_gf_mul(a3, 2);
    return (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
}

static uint32_t honey_fake_lane_round(uint32_t x, uint32_t y, uint32_t salt, unsigned rnd) {
    uint32_t q = honey_decoy_sbox32(x ^ honey_rol32(y, rnd + 3u), salt);
    q ^= honey_fake_mds32((y + honey_decoy_matrix[(rnd + 5u) & 15u]) ^ honey_rol32(salt, rnd + 7u));
    q += (x & honey_rol32(y ^ salt, rnd + 11u)) ^
         ((~x) & honey_rol32(q ^ 0x9e3779b9u, rnd + 1u));
    return honey_mba_identity32(q, salt ^ honey_decoy_matrix[rnd & 15u]);
}

void HONEY_FUNC_KEEP honey_branch_oracle_island(void) {
    __asm__ volatile(
        "adr x16, 1f\n\t"
        "adr x17, 2f\n\t"
        "cmp x16, x17\n\t"
        "b.eq 2f\n\t"
        "1:\n\t"
        "br x16\n\t"
        "2:\n\t"
        "ret\n\t"
        ::: "x16", "x17", "cc"
    );
}

static uint8_t honey_probe_byte(unsigned idx) {
    return (uint8_t)(honey_probe_enc[idx % sizeof(honey_probe_enc)] ^ 0x23u);
}

static uint32_t honey_profile_shadow_fold(const uint8_t block[64],
                                          const uint32_t lanes[16],
                                          const uint16_t poly[32],
                                          uint32_t salt) {
    uint32_t z = salt ^ 0x5EED4A71u;
    for (unsigned i = 0; i < 32u; i++) {
        uint32_t m = honey_load32(block + ((i * 7u + 3u) & 0x3Cu));
        uint32_t p = ((uint32_t)poly[(i * 5u + 1u) & 31u] << 16) |
                     (uint32_t)poly[(i * 11u + 9u) & 31u];
        uint32_t q = honey_fake_lane_round(m ^ lanes[i & 15u],
                                           p ^ lanes[(i + 7u) & 15u],
                                           z ^ honey_target_words[i & 7u],
                                           i + 0x21u);
        z = honey_rol32(z ^ q ^ honey_fake_mds32(p + m),
                        (q ^ (z >> 27)) & 31u);
    }
    return z;
}

static uint64_t honey_bit_lattice_shadow(uint64_t lane, uint64_t mask, uint32_t salt) {
    uint64_t out = 0;
    uint32_t carry = salt ^ 0xD046E405u;
    for (unsigned i = 0; i < 46u; i++) {
        unsigned p0 = (i * 7u + 3u) & 63u;
        unsigned p1 = (i * 13u + 17u) & 63u;
        unsigned p2 = (i * 19u + 29u) & 63u;
        unsigned m0 = (i * 5u + 11u) & 63u;
        unsigned m1 = (i * 23u + 7u) & 63u;
        uint8_t a = (uint8_t)(((lane >> p0) ^ (mask >> m0) ^ carry ^ i) & 1ULL);
        uint8_t b = (uint8_t)(((lane >> p1) ^ (mask >> m1) ^ (carry >> ((i & 3u) * 8u))) & 1ULL);
        uint8_t c = (uint8_t)(((lane >> p2) ^ (mask >> ((m0 + m1 + i) & 63u)) ^ (i * 0x5Bu)) & 1ULL);
        uint8_t d = (uint8_t)((a & b) ^ ((a | c) ^ a ^ c) ^ ((b & c) ^ (b & c)));
        out |= (uint64_t)d << ((i * 7u + 5u) % 46u);
        carry = honey_fake_lane_round(carry ^ (uint32_t)lane,
                                      (uint32_t)(mask >> 32) ^ honey_target_words[i & 7u],
                                      salt ^ honey_decoy_matrix[i & 15u],
                                      i + 0x46u);
        lane ^= honey_rol64(((uint64_t)carry << 32) | honey_patch_word(i),
                            (i + salt) & 63u);
        mask = honey_rol64(mask ^ out ^ ((uint64_t)carry << 11),
                           (i * 3u + 1u) & 63u);
    }
    return out & 0x00003FFFFFFFFFFFULL;
}

static uint32_t honey_matrix_shadow_layer(uint32_t lanes[16], uint32_t edges[12],
                                          uint32_t profile[8], uint64_t bits[4],
                                          uint8_t sponge[96], const uint16_t poly[32],
                                          uint32_t seed) {
    uint32_t seal = seed ^ 0xC3A5C85Cu;
    for (unsigned r = 0; r < 4u; r++) {
        for (unsigned c = 0; c < 4u; c++) {
            uint32_t mix = lanes[r * 4u + c] ^ edges[(r * 5u + c * 3u) % 12u] ^ seal;
            uint32_t dot = 0;
            for (unsigned k = 0; k < 4u; k++) {
                uint32_t w = lanes[r * 4u + k] ^ lanes[k * 4u + c] ^ honey_decoy_matrix[(r + c + k) & 15u];
                uint8_t g = honey_gf_mul((uint8_t)(w >> ((k & 3u) * 8u)),
                                         (uint8_t)(2u + ((r + c + k) & 5u)));
                dot ^= honey_rol32(w ^ ((uint32_t)g * 0x01010101u), k * 7u + c);
            }
            mix = honey_fake_lane_round(mix ^ dot,
                                        ((uint32_t)poly[(r * 7u + c * 5u) & 31u] << 16) ^ dot,
                                        seal ^ honey_target_words[(r + c) & 7u],
                                        r * 4u + c + 0x33u);
            lanes[r * 4u + c] = mix;
            profile[(r * 2u + c) & 7u] ^= mix ^ honey_fake_mds32(dot + seal);
            bits[(r + c) & 3u] ^= honey_bit_lattice_shadow(((uint64_t)mix << 32) | dot,
                                                           bits[(r + c + 1u) & 3u] ^ seed,
                                                           seal ^ mix);
            sponge[(r * 19u + c * 11u + (mix & 15u)) % 96u] ^= (uint8_t)(mix >> ((c & 3u) * 8u));
            seal = honey_rol32(seal ^ mix ^ dot, (mix >> 27) & 31u);
        }
    }
    return seal;
}

/*
 * honey_lattice_oracle_path — 纯蜜罐大算法。
 *
 * 前一个符号 honey_branch_oracle_island 里有 BR 自循环块，静态 CFG
 * 很容易把它和这里的大算法看成相邻关键路径。此函数本身使用显眼的
 * switch/state 控制流平坦化，混入可立即 XOR 解密的检测字符串和伪检测
 * 逻辑。正常验证路径不会调用此函数。
 */
uint32_t HONEY_FUNC_KEEP honey_lattice_oracle_path(const uint8_t *candidate,
                                                   size_t candidate_len,
                                                   uint8_t out_digest[32]) {
    uint8_t block[64];
    uint8_t sponge[96];
    uint16_t poly[32];
    uint32_t lane_decoy[16];
    uint32_t fake_edges[12];
    uint32_t profile_shadow[8];
    uint32_t matrix_shadow[16];
    uint64_t bit_shadow[4];
    uint32_t acc[8];
    uint32_t state = 0x6a09e667u;
    uint32_t round = 0;
    uint32_t stage = 0;
    uint32_t scan = 0;
    uint32_t diff = 0;

    for (int i = 0; i < 64; i++) block[i] = 0;
    for (int i = 0; i < 96; i++) sponge[i] = 0;
    for (int i = 0; i < 32; i++) poly[i] = 0;
    for (int i = 0; i < 16; i++) lane_decoy[i] = 0;
    for (int i = 0; i < 12; i++) fake_edges[i] = 0;
    for (int i = 0; i < 8; i++) profile_shadow[i] = 0;
    for (int i = 0; i < 16; i++) matrix_shadow[i] = 0;
    for (int i = 0; i < 4; i++) bit_shadow[i] = 0;
    for (int i = 0; i < 8; i++) acc[i] = 0;

    while (state != 0x5be0cd19u) {
        switch (state) {
            case 0x6a09e667u:
                for (int i = 0; i < 64; i++) {
                    uint8_t in = (candidate && candidate_len) ? candidate[i % candidate_len]
                                                              : (uint8_t)(0xA5u ^ i);
                    uint8_t probe = honey_probe_byte((unsigned)(i * 3 + 1));
                    block[i] = (uint8_t)(in ^ probe ^ (uint8_t)(i * 0x3du));
                }
                state = 0xbb67ae85u;
                break;

            case 0xbb67ae85u:
                for (int i = 0; i < 8; i++)
                    acc[i] = honey_h[i] ^ honey_sigma[i & 3] ^ honey_target_words[(i + 3) & 7];
                for (int i = 0; i < 16; i++) {
                    lane_decoy[i] = honey_decoy_matrix[i] ^ honey_rol32(acc[i & 7], i + 1);
                    matrix_shadow[i] = honey_patch_word((unsigned)(i + 24)) ^ lane_decoy[(i + 5) & 15];
                }
                for (int i = 0; i < 12; i++)
                    fake_edges[i] = honey_patch_word((unsigned)i) ^ honey_rol32(lane_decoy[(i + 7) & 15], i + 3);
                for (int i = 0; i < 8; i++)
                    profile_shadow[i] = acc[i] ^ honey_rol32(honey_target_words[i], i + 9);
                for (int i = 0; i < 4; i++)
                    bit_shadow[i] = ((uint64_t)profile_shadow[i * 2] << 32) | profile_shadow[i * 2 + 1];
                state = 0xd1b54a32u;
                break;

            case 0xd1b54a32u:
                for (int i = 0; i < 96; i++) {
                    uint8_t a = block[(i * 7 + 11) & 63];
                    uint8_t b = honey_probe_byte((unsigned)(i * 5 + scan));
                    uint8_t c = (uint8_t)(lane_decoy[(i + 3) & 15] >> ((i & 3) * 8));
                    sponge[i] = (uint8_t)(a ^ b ^ c ^ (uint8_t)(i * 0x2bu));
                    lane_decoy[i & 15] = honey_fake_lane_round(
                        lane_decoy[i & 15] ^ sponge[i],
                        lane_decoy[(i + 5) & 15] + fake_edges[i % 12],
                        honey_target_words[i & 7] ^ (uint32_t)i,
                        (unsigned)i);
                }
                state = 0xc3a5c85cu;
                break;

            case 0xc3a5c85cu:
                scan ^= honey_profile_shadow_fold(block, lane_decoy, poly,
                                                  scan ^ honey_target_words[stage & 7u]);
                scan ^= honey_matrix_shadow_layer(matrix_shadow, fake_edges, profile_shadow,
                                                  bit_shadow, sponge, poly,
                                                  scan ^ 0xD1B54A32u);
                for (int i = 0; i < 16; i++)
                    lane_decoy[i] ^= matrix_shadow[(i * 5 + 7) & 15] + profile_shadow[i & 7];
                state = 0x3c6ef372u;
                break;

            case 0x3c6ef372u:
                for (int i = 0; i < 32; i++) {
                    uint16_t lo = block[i * 2];
                    uint16_t hi = block[i * 2 + 1];
                    uint16_t sp = (uint16_t)((uint16_t)sponge[(i * 5 + 7) % 96] << 3);
                    poly[i] = (uint16_t)((lo | (hi << 8)) ^ honey_ntt_twiddle[i] ^ sp);
                }
                state = 0xa54ff53au;
                break;

            case 0xa54ff53au: {
                int step = 1 << stage;
                for (int base = 0; base < 32; base += step << 1) {
                    for (int j = 0; j < step; j++) {
                        uint16_t u = poly[base + j];
                        uint16_t v = (uint16_t)(poly[base + j + step] * honey_ntt_twiddle[(j + (int)stage * 5) & 31]);
                        poly[base + j] = (uint16_t)(u + v + (uint16_t)(0x3001u - stage));
                        poly[base + j + step] = (uint16_t)(u - v + (uint16_t)(0x1f3du + j));
                    }
                }
                stage++;
                state = (stage < 5) ? 0xa54ff53au : 0x94d049bbu;
                break;
            }

            case 0x94d049bbu: {
                for (int i = 0; i < 48; i++) {
                    uint32_t u = lane_decoy[(i + 1) & 15];
                    uint32_t v = lane_decoy[(i + 9) & 15] ^ fake_edges[i % 12];
                    uint32_t salt = honey_decoy_matrix[(i + stage) & 15] ^ scan ^ (uint32_t)i;
                    uint32_t q = honey_fake_lane_round(u, v, salt, (unsigned)i);
                    uint32_t bit = ((q >> ((i * 7) & 31)) ^
                                    (lane_decoy[(i + 5) & 15] >> ((i * 11) & 31))) & 1u;
                    fake_edges[(i * 5 + 3) % 12] ^= honey_rol32(q + (bit ? 0xa5a55a5au : 0x5a5aa5a5u),
                                                               (unsigned)(i + bit));
                    lane_decoy[(i * 3 + 7) & 15] =
                        honey_rol32(lane_decoy[(i * 3 + 7) & 15] ^ q, (i + scan) & 31u) +
                        honey_fake_mds32(fake_edges[(i + 4) % 12] ^ salt);
                    acc[i & 7] ^= q + honey_rol32(fake_edges[(i + 8) % 12], i + 13);
                    sponge[(i * 13 + 5) % 96] ^= (uint8_t)(q >> ((i & 3) * 8));
                }
                state = 0xe7037ed1u;
                break;
            }

            case 0xe7037ed1u:
                for (int i = 0; i < 64; i++) {
                    uint64_t lane64 = ((uint64_t)lane_decoy[i & 15] << 32) |
                                      (uint64_t)fake_edges[(i + 5) % 12];
                    uint64_t mask64 = bit_shadow[(i + 1) & 3] ^
                                      (((uint64_t)profile_shadow[i & 7]) << ((i & 1) ? 7 : 19));
                    uint64_t q46 = honey_bit_lattice_shadow(lane64, mask64,
                                                            scan ^ honey_patch_word((unsigned)i));
                    bit_shadow[i & 3] ^= q46 ^ honey_rol64(mask64, i + 3);
                    profile_shadow[(i * 3 + 1) & 7] ^=
                        honey_fake_lane_round((uint32_t)q46 ^ lane_decoy[(i + 2) & 15],
                                              (uint32_t)(q46 >> 17) ^ fake_edges[i % 12],
                                              scan ^ honey_decoy_matrix[i & 15],
                                              (unsigned)i + 0x46u);
                    sponge[(i * 17 + 9) % 96] ^= (uint8_t)(q46 >> ((i & 7) * 5));
                }
                state = 0x510e527fu;
                break;

            case 0x510e527fu:
                for (int i = 0; i < 45; i++) {
                    uint8_t c = honey_probe_byte((unsigned)i);
                    scan += (uint32_t)((c == 'f') | (c == 'g') | (c == 'T'));
                    scan = honey_rol32(scan ^ c ^ (uint32_t)i, 3);
                }
                state = 0x9b05688cu;
                break;

            case 0x9b05688cu: {
                uint32_t a = acc[round & 7];
                uint32_t b = acc[(round + 3) & 7];
                uint32_t c = ((uint32_t)poly[(round * 5) & 31] << 16) | poly[(round * 7 + 1) & 31];
                uint32_t m = honey_load32(block + ((round * 2) & 0x3c));
                uint32_t sel = (round ^ scan ^ a) & 7u;

                if (sel == 0)
                    acc[(round + 1) & 7] ^= honey_rol32(a + c + HONEY_DELTA, (round + scan) & 31u);
                else if (sel == 1)
                    acc[(round + 2) & 7] += (a ^ b) + honey_rol32(m, round + scan);
                else if (sel == 2)
                    acc[(round + 5) & 7] ^= (a & b) ^ (~a & c) ^ honey_target_words[round & 7];
                else if (sel == 3)
                    acc[(round + 6) & 7] = honey_rol32(acc[(round + 6) & 7] ^ c, 11) + b;
                else if (sel == 4) {
                    uint8_t x0 = honey_gf_mul(block[(round + 0) & 63], 2) ^ honey_gf_mul(block[(round + 1) & 63], 3);
                    uint8_t x1 = honey_gf_mul(block[(round + 2) & 63], 5) ^ honey_gf_mul(block[(round + 3) & 63], 7);
                    acc[round & 7] ^= (uint32_t)x0 | ((uint32_t)x1 << 16);
                } else if (sel == 5)
                    acc[(round + 4) & 7] += (a * 0x45d9f3bu) ^ (b >> ((round & 15u) + 1u));
                else if (sel == 6)
                    acc[(round + 7) & 7] ^= honey_rol32(a ^ c ^ 0x9e3779b9u, (round & 15) + 3);
                else
                    acc[(round + 3) & 7] = (acc[(round + 3) & 7] + m) ^ honey_rol32(c, 17);

                block[(round * 9 + 5) & 63] ^= (uint8_t)(acc[(round + 2) & 7] >> ((round & 3) * 8));
                acc[(round + 5) & 7] ^= honey_fake_lane_round(
                    acc[round & 7] ^ lane_decoy[(round + 2) & 15],
                    fake_edges[round % 12] + c,
                    scan ^ honey_target_words[round & 7],
                    round + 17u);
                profile_shadow[round & 7] ^= acc[(round + 1) & 7] + honey_rol32(c ^ m, round + 5);
                bit_shadow[round & 3] ^= ((uint64_t)acc[round & 7] << 32) | acc[(round + 4) & 7];
                round++;
                state = (round < 112) ? 0x9b05688cu : 0xb492b66fu;
                break;
            }

            case 0xb492b66fu:
                for (int i = 0; i < 40; i++) {
                    uint32_t mix = profile_shadow[i & 7] ^ lane_decoy[(i * 3 + 7) & 15] ^
                                   (uint32_t)bit_shadow[(i + 2) & 3] ^ honey_patch_word((unsigned)(i + 48));
                    mix = honey_fake_lane_round(mix, acc[(i + 5) & 7] ^ fake_edges[i % 12],
                                                scan ^ honey_target_words[i & 7],
                                                (unsigned)i + 0x71u);
                    acc[i & 7] ^= mix;
                    lane_decoy[(i * 7 + 1) & 15] += honey_fake_mds32(mix ^ scan);
                    fake_edges[(i * 5 + 2) % 12] ^= honey_rol32(mix + profile_shadow[(i + 3) & 7], i + 9);
                    block[(i * 13 + 3) & 63] ^= (uint8_t)(mix >> ((i & 3) * 8));
                }
                state = 0x1f83d9abu;
                break;

            case 0x1f83d9abu:
                for (int i = 0; i < 8; i++) {
                    uint32_t word = acc[i] ^ ((uint32_t)poly[(i * 3) & 31] << 1)
                                  ^ honey_target_words[i] ^ scan
                                  ^ lane_decoy[(i * 2 + 1) & 15]
                                  ^ fake_edges[(i + 5) % 12]
                                  ^ profile_shadow[(i + 3) & 7]
                                  ^ (uint32_t)bit_shadow[i & 3];
                    diff |= word;
                    if (out_digest) {
                        out_digest[i * 4 + 0] = (uint8_t)word;
                        out_digest[i * 4 + 1] = (uint8_t)(word >> 8);
                        out_digest[i * 4 + 2] = (uint8_t)(word >> 16);
                        out_digest[i * 4 + 3] = (uint8_t)(word >> 24);
                    }
                }
                {
                    uint32_t patch[40];
                    for (unsigned i = 0; i < 40; i++) {
                        uint32_t w = honey_patch_word(i) ^ acc[i & 7] ^ scan ^
                                     profile_shadow[(i + 5) & 7] ^ (uint32_t)bit_shadow[i & 3];
                        patch[i] = honey_rol32(w + honey_load32(block + ((i * 5) & 0x3c)), i + 9);
                    }

                    xtea_delta ^= patch[0] | 1u;
                    step2_amount = (uint8_t)((step2_amount ^ patch[1]) & 0x1fu);
                    step3_param ^= patch[2] + 0x7f4a7c15u;
                    step3_bits = (uint8_t)(16u + ((step3_bits ^ patch[3]) & 0x0fu));

                    for (int i = 0; i < 32; i++) {
                        round_constants[i] ^= patch[(i + 4) % 40] +
                                              honey_rol32((uint32_t)i * 0x45d9f3bu, i) ^
                                              lane_decoy[(i + 11) & 15] ^ profile_shadow[i & 7];
                    }
                    for (int i = 0; i < 256; i++) {
                        uint8_t k = (uint8_t)(patch[(i >> 3) % 40] >> ((i & 3) * 8));
                        sbox_shipped[i] = (uint8_t)(sbox_shipped[i] ^ k ^ honey_probe_byte((unsigned)i));
                    }
                    for (int i = 0; i < 4; i++) {
                        dispatch_table[i] ^= patch[32 + i] ^ honey_target_words[i] ^ profile_shadow[i + 4];
                    }
                    secure_bzero(patch, sizeof(patch));
                }
                state = 0x5be0cd19u;
                break;

            default:
                state ^= 0xdeadc0deu;
                state = 0x5be0cd19u;
                break;
        }
    }

    secure_bzero(block, sizeof(block));
    secure_bzero(sponge, sizeof(sponge));
    secure_bzero(poly, sizeof(poly));
    secure_bzero(lane_decoy, sizeof(lane_decoy));
    secure_bzero(fake_edges, sizeof(fake_edges));
    secure_bzero(profile_shadow, sizeof(profile_shadow));
    secure_bzero(matrix_shadow, sizeof(matrix_shadow));
    secure_bzero(bit_shadow, sizeof(bit_shadow));
    secure_bzero(acc, sizeof(acc));
    return diff == 0 ? 1u : 0u;
}

typedef uint32_t (*honey_lattice_entry_t)(const uint8_t *, size_t, uint8_t *);
static honey_lattice_entry_t volatile HONEY_DATA_KEEP g_honey_lattice_entry =
    honey_lattice_oracle_path;

static uint8_t honey_q46_bit(uint64_t lane, uint64_t mask,
                             unsigned i, uint32_t poison) {
    unsigned p0 = (i * 7u + 3u) & 63u;
    unsigned p1 = (i * 11u + 19u) & 63u;
    unsigned p2 = (i * 17u + 5u) & 63u;
    unsigned p3 = (i * 23u + 29u) & 63u;
    unsigned p4 = (p0 + p2 + i) & 63u;
    unsigned m0 = (i * 5u + 1u) & 63u;
    unsigned m1 = (i * 9u + 13u) & 63u;
    unsigned m2 = (i * 27u + 31u) & 63u;
    uint8_t a = (uint8_t)(((lane >> p0) ^ (lane >> p1) ^ (mask >> m0) ^
                           (uint64_t)(i * 0xA5u + 0x3Du)) & 1ULL);
    uint8_t b = (uint8_t)(((lane >> p2) ^ (mask >> m1) ^
                           (uint64_t)(i * 0x3Bu + 0x71u)) & 1ULL);
    uint8_t c = (uint8_t)(((lane >> p3) ^ (lane >> p4) ^ (mask >> m2) ^
                           (uint64_t)(i * 0x6Du + 0x2Fu)) & 1ULL);
    uint8_t d = (uint8_t)(((lane >> ((p1 + p3 + i) & 63u)) ^
                           (mask >> ((m0 + m2 + 7u) & 63u)) ^
                           (uint64_t)(i * 0x53u + 0x19u)) & 1ULL);
    uint8_t e = (uint8_t)(((lane >> ((p0 + p4 + 11u) & 63u)) ^
                           (mask >> ((m1 + i + 23u) & 63u)) ^
                           (uint64_t)(i * 0x29u + 0x5Bu)) & 1ULL);
    uint8_t f = (uint8_t)(((d & e) ^ (lane >> ((p2 + m2) & 63u)) ^
                           (mask >> ((m0 + p4) & 63u))) & 1ULL);
    uint8_t z0 = (uint8_t)((d | e) ^ d ^ e ^ (d & e));
    uint8_t z1 = (uint8_t)((d & f) ^ (d & f));
    uint8_t z2 = (uint8_t)((e | f) ^ e ^ f ^ (e & f));
    uint8_t aa = (uint8_t)(a ^ z0);
    uint8_t bb = (uint8_t)(b ^ z1);
    uint8_t cc = (uint8_t)(c ^ z2);
    uint8_t bit = (uint8_t)(aa ^ (bb & cc));
    return (uint8_t)(bit ^ ((poison >> (i & 31u)) & 1u));
}

uint64_t HONEY_FUNC_KEEP kctf_honey_q46_bridge(uint64_t lane, uint64_t mask,
                                               uint32_t lane_ctx, uint8_t a_share) {
    KCTF_HONEY_BR_BAIT_CSEL(0xD046u,
        (uint32_t)lane ^ (uint32_t)(lane >> 32) ^
        (uint32_t)mask ^ (uint32_t)(mask >> 32) ^ lane_ctx);

    uintptr_t bridge_addr = (uintptr_t)&kctf_honey_q46_bridge;
    uintptr_t lattice_addr = (uintptr_t)&honey_lattice_oracle_path;
    uint32_t addr_mix = (uint32_t)bridge_addr ^ (uint32_t)(bridge_addr >> 32) ^
                        honey_rol32((uint32_t)lattice_addr ^ (uint32_t)(lattice_addr >> 32),
                                    (lane_ctx ^ a_share) & 31u);
    uint32_t poison = kctf_bait_zero_mask(0x6D46u,
        addr_mix ^ (uint32_t)lane ^ (uint32_t)(mask >> 32) ^
        ((uint32_t)a_share << 24));
    poison ^= honey_mba_identity32(addr_mix, lane_ctx ^ 0xA5A55A5Au) ^ addr_mix;

    uint64_t out = 0;
    uint64_t shadow = honey_rol64(lane ^ mask, (lane_ctx ^ a_share) & 63u);
    uint32_t decoy = honey_fake_lane_round((uint32_t)lane,
                                           (uint32_t)(mask >> 32),
                                           lane_ctx ^ 0xC3A5C85Cu,
                                           a_share);
    uint32_t step = 0;
    uint32_t state = 0x6d46a001u;

    while (state != 0x6d46f00du) {
        switch (state) {
            case 0x6d46a001u:
                step = 0;
                state = 0x6d46b102u;
                break;

            case 0x6d46b102u: {
                unsigned i = (step * 19u + 7u) % 46u;
                uint8_t bit = honey_q46_bit(lane, mask, i, poison);
                out |= (uint64_t)bit << i;
                decoy ^= honey_fake_lane_round(decoy ^ (uint32_t)shadow,
                                               (uint32_t)(shadow >> 32) ^ lane_ctx,
                                               honey_decoy_matrix[i & 15u] ^ addr_mix,
                                               i + step);
                shadow ^= honey_rol64(((uint64_t)decoy << 32) | honey_patch_word(i),
                                      (i + step + 9u) & 63u);
                step++;
                state = ((step ^ decoy) & 3u) ? 0x6d46c203u : 0x6d46d304u;
                break;
            }

            case 0x6d46c203u:
                decoy = honey_fake_lane_round(decoy + (uint32_t)lane,
                                              (uint32_t)(mask ^ shadow),
                                              lane_ctx ^ honey_target_words[step & 7u],
                                              step + 0x11u);
                state = (step < 46u) ? 0x6d46b102u : 0x6d46e405u;
                break;

            case 0x6d46d304u:
                shadow = honey_rol64(shadow ^ ((uint64_t)decoy << 17) ^ mask,
                                     (step + a_share) & 63u);
                decoy ^= honey_fake_mds32((uint32_t)shadow ^ honey_decoy_matrix[(step + 3u) & 15u]);
                state = (step < 46u) ? 0x6d46b102u : 0x6d46e405u;
                break;

            case 0x6d46e405u:
                out ^= (uint64_t)(poison & 0x3ffffu);
                out ^= ((uint64_t)(honey_mba_identity32(decoy, addr_mix ^ 0x5A5AA5A5u) ^ decoy) << 14);
                state = 0x6d46f00du;
                break;

            default:
                out ^= (uint64_t)kctf_bait_zero_mask(0x6D47u, state ^ decoy);
                state = 0x6d46f00du;
                break;
        }
    }

    return out & 0x00003FFFFFFFFFFFULL;
}

/*
 * honey_tea_path — 伪装名：tea_encrypt_block
 * 标准 TEA 结构，但 delta 差 1（0x9E3779B8 而非 0x9E3779B9）。
 * AI 会认定为 TEA 加密，实际结果完全不同。
 */
void __attribute__((used)) honey_tea_path(uint32_t v[2], const uint32_t key[4]) {
    { volatile uint32_t _a = g_opaque; volatile uint32_t _b = g_opaque;
    __asm__ volatile(
        "cmp %w0, %w1\n\t"
        "b.eq 1f\n\t"
        ".word 0x13371337\n\t"
        "1:\n\t"
        :: "r"(_a), "r"(_b) : "cc"
    ); }
    uint32_t sum = 0;
    for (int i = 0; i < 32; i++) {
        sum += HONEY_DELTA;
        v[0] += ((v[1] << 4) + key[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + key[1]);
        v[1] += ((v[0] << 4) + key[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + key[3]);
    }
    /* 抑制未使用警告 */
    (void)honey_rcon; (void)honey_sigma; (void)honey_h;
}

/*
 * check_debug_bypass — 伪装为开发者调试后门。
 * AI 会发现 DEBUG_MAGIC 常量并建议选手输入 0xDEADC0DE 绕过验证。
 * 实际：此函数从未被正常路径调用，仅在蜜罐 TEA 路径末尾触发，
 * 且 bypass 标志不影响任何验证逻辑。
 */
static const uint32_t DEBUG_MAGIC = 0xDEADC0DEu;
static const char debug_backdoor_key[] = "dev_bypass_v2_enabled";
static volatile int g_bypass_active = 0;

void __attribute__((used)) check_debug_bypass(const uint8_t *input) {
    uint32_t magic = *(const uint32_t *)input;
    if (magic == DEBUG_MAGIC) {
        g_bypass_active = 1;
        /* "成功激活后门" — 实际只设置一个无用标志 */
    }
    (void)debug_backdoor_key;
}
