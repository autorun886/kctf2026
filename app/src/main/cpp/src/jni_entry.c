#include <jni.h>
#include <stdint.h>
#include <string.h>
#include "include/kctf.h"
#include "include/const_xor.h"

/* ── 硬编码 IV（方案 B）─────────────────────────────────── */
static volatile const uint8_t IV[STATE_LEN] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
};

/* 方案 B 第一次 SPN 目标分片（converge.py 填入） */
static volatile const uint8_t ENC_EXPECTED_STATE_S0[STATE_LEN] = {
    0xFD, 0x1C, 0xA7, 0x90, 0x38, 0x2C, 0xD2, 0x55,
    0x6C, 0x97, 0xE7, 0xCF, 0x01, 0xF1, 0x01, 0xD7
};
static volatile const uint8_t ENC_EXPECTED_STATE_S1[STATE_LEN] = {
    0xAC, 0x1D, 0x8E, 0xFF, 0x70, 0xE1, 0x52, 0xC3,
    0x34, 0xA5, 0x16, 0x87, 0xF8, 0x69, 0xDA, 0x4B
};

/* ── 第二 IV（唯一性约束，与 IV1 不同）──────────────────── */
static volatile const uint8_t IV2[STATE_LEN] = {
    0xA5,0x5A,0xC3,0x3C,0xF0,0x0F,0x69,0x96,
    0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0
};

/* 方案 B 第二次 SPN 目标分片（converge.py 填入） */
static volatile const uint8_t ENC_EXPECTED_STATE2_S0[STATE_LEN] = {
    0xE4, 0x2A, 0xAA, 0xDA, 0x29, 0xF8, 0x50, 0x90,
    0x78, 0xCA, 0x30, 0x70, 0xF3, 0x45, 0x35, 0xCF
};
static volatile const uint8_t ENC_EXPECTED_STATE2_S1[STATE_LEN] = {
    0x36, 0xA7, 0x18, 0x89, 0xFA, 0x6B, 0xDC, 0x4D,
    0xBE, 0x2F, 0xA0, 0x11, 0x82, 0xF3, 0x64, 0xD5
};

/* const_xor piece 2: LE_u32(IV[0:4]) ^ LE_u32(IV2[0:4]) — 耦合到 const_xor.c */
uint32_t cxk_get_piece2(void) {
    uint32_t a = (uint32_t)IV[0] | ((uint32_t)IV[1] << 8)
              | ((uint32_t)IV[2] << 16) | ((uint32_t)IV[3] << 24);
    uint32_t b = (uint32_t)IV2[0] | ((uint32_t)IV2[1] << 8)
              | ((uint32_t)IV2[2] << 16) | ((uint32_t)IV2[3] << 24);
    return a ^ b;
}

/* 方案 A 目标状态分片（converge.py 填入） */
static volatile const uint8_t ENC_EXPECTED_STATE_A_S0[STATE_LEN] = {
    0xDF, 0xC9, 0x64, 0xA0, 0x13, 0x14, 0x4F, 0xE5,
    0xE0, 0x87, 0x02, 0x5D, 0x5E, 0x5D, 0x4E, 0xE2
};
static volatile const uint8_t ENC_EXPECTED_STATE_A_S1[STATE_LEN] = {
    0x50, 0xC1, 0x32, 0xA3, 0x14, 0x85, 0xF6, 0x67,
    0xD8, 0x49, 0xBA, 0x2B, 0x9C, 0x0D, 0x7E, 0xEF
};

/*
 * material[8:16] 投影常量分片（converge.py 填入）。
 * 不再用 uint32_t[3] 顺序摆放，避免静态搜索直接命中 12 字节锚点。
 */
static volatile const uint8_t MATERIAL_SHARD_BANK[31] = {
    0x31, 0x54, 0xA7, 0x02, 0xDB, 0x46, 0x90, 0xE5,
    0x22, 0x77, 0x8C, 0xF4, 0xFF, 0x6D, 0x55, 0x15,
    0x13, 0xD5, 0x40, 0xBE, 0x34, 0xD9, 0x73, 0x03,
    0x96, 0x5B, 0xD9, 0x84, 0xBA, 0xEF, 0x02
};
static volatile const uint8_t MATERIAL_SHARD_ROUTE[12] = {
    0x4B, 0x6E, 0x97, 0x9B, 0xA7, 0xA3,
    0xC0, 0xCB, 0xF7, 0x0A, 0x04, 0x21
};
/* fake material corruption syndrome 分片（converge.py 填入） */
static volatile const uint8_t MATERIAL_FAKE_SYNDROME_SHARD = 0x85u;
/* Scheme A share 版本补偿（converge.py 填入，稳定公开 Q46 目标实例） */
static volatile const uint8_t SCHEME_A_SHARE_TUNE = 0x2au;

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t load_le64(const uint8_t *p) {
    return (uint64_t)load_le32(p) | ((uint64_t)load_le32(p + 4) << 32);
}

static uint32_t rol32(uint32_t x, unsigned n) {
    n &= 31u;
    return n ? (uint32_t)((x << n) | (x >> (32u - n))) : x;
}

static uint32_t ror32(uint32_t x, unsigned n) {
    n &= 31u;
    return n ? (uint32_t)((x >> n) | (x << (32u - n))) : x;
}

static uint64_t rol64(uint64_t x, unsigned n) {
    n &= 63u;
    return n ? (uint64_t)((x << n) | (x >> (64u - n))) : x;
}

static uint32_t material_generated_mask32(unsigned slot) {
    uint32_t x = 0x6D46A001u ^ (slot * 0x9E3779B9u);
    x ^= 0x85EBCA77u + slot * 0x27D4EB2Fu;
    for (unsigned i = 0; i < 5; i++) {
        uint32_t t = (0xC3A5C85Cu + slot * 0x165667B1u + i * 0x7F4A7C15u);
        t ^= t >> 13;
        t *= 0x9E3779B9u;
        t ^= t >> 16;
        x ^= rol32(t, (slot + i * 3u + 5u) & 31u);
        x ^= x >> 15;
        x *= 0x2C1B3C6Du;
        x ^= x >> 12;
        x *= 0x297A2D39u;
        x = rol32(x, ((slot + 1u) * 5u + i * 7u) & 31u);
    }
    return x ^ 0xB492B66Fu;
}

static uint8_t material_shard_static_mask8(unsigned pos) {
    uint32_t x = 0xB7E15163u ^ (pos * 0x9E3779B9u);
    x ^= rol32(0x243F6A88u + pos * 0x85EBCA77u, (pos * 5u + 3u) & 31u);
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return (uint8_t)(x ^ (x >> 8) ^ (x >> 19));
}

static uint32_t material_code_shadow_zero32(unsigned slot) {
    const volatile uint8_t *code =
        (const volatile uint8_t *)(const void *)(uintptr_t)&material_code_shadow_zero32;
    uint32_t mix = 0x510E527Fu ^ (slot * 0x1B873593u);
    for (unsigned i = 0; i < 4; i++) {
        uint32_t b = code[(slot * 13u + i * 7u + 3u) & 63u];
        mix ^= b << (i * 8u);
        mix = rol32(mix * 0x85EBCA77u, (b & 7u) + 1u);
    }
    uint32_t shadow = mix;
    __asm__ volatile("" : "+r"(mix));
    __asm__ volatile("" : "+r"(shadow));
    return mix ^ shadow;
}

static uint8_t material_generated_mask8(unsigned slot) {
    uint32_t x = material_generated_mask32(slot) ^ rol32(material_generated_mask32(slot + 5u), 11u);
    x ^= material_code_shadow_zero32(slot + 9u);
    return (uint8_t)(x ^ (x >> 8) ^ (x >> 16) ^ (x >> 24));
}

static uint32_t load_material_expected_enc(unsigned slot) {
    uint32_t shard = 0;
    unsigned base = (slot % 3u) * 4u;
    for (unsigned i = 0; i < 4; i++) {
        unsigned pos = base + i;
        uint8_t route = (uint8_t)(MATERIAL_SHARD_ROUTE[pos] ^
                                  (uint8_t)(0x5Au + pos * 0x13u));
        uint8_t b = MATERIAL_SHARD_BANK[route % (unsigned)sizeof(MATERIAL_SHARD_BANK)];
        b ^= material_shard_static_mask8(pos);
        b ^= (uint8_t)material_code_shadow_zero32(pos + 0x31u);
        shard |= (uint32_t)b << (i * 8u);
    }
    return shard ^ material_generated_mask32(slot) ^ material_code_shadow_zero32(slot);
}

static uint8_t load_material_fake_syndrome_enc(void) {
    return MATERIAL_FAKE_SYNDROME_SHARD ^ material_generated_mask8(3u);
}

static uint8_t sokey_share_mask(int i) {
    return (uint8_t)(((0x6Du + (uint32_t)i * 0x3Bu) ^ ((uint32_t)i * 0x1Du)) & 0xFFu);
}

#define JAVA_PROFILE_SEED_DEFAULT 0x5EED4A71u

static uint32_t java_profile_runtime_seed(void) {
    uint32_t x = kctf_guard_anchor() ^ 0xA91D3B05u;
    x ^= rol32((uint32_t)((uintptr_t)(const void *)&java_profile_runtime_seed >> 4), 5u);
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    x ^= JAVA_PROFILE_SEED_DEFAULT ^ 0xD046E405u;
    return x ? x : (JAVA_PROFILE_SEED_DEFAULT ^ 0x13579BDFu);
}

static uint32_t java_archive_profile_word(const uint8_t meta[32], uint32_t seed) {
    uint32_t x = seed ^ 0x6B02C3A5u;
    uint32_t crc = load_le32(meta + 16);
    uint32_t off = load_le32(meta + 20);
    uint32_t size = load_le32(meta + 24);
    uint32_t acc = crc ^ rol32(off + 0x27D4EB2Fu, 7u)
                 ^ ror32(size ^ 0xA0761D64u, 3u);
    unsigned idx = 0;
    unsigned pc = 0x12u;
    for (;;) {
        switch (pc) {
            case 0x12u:
                x ^= acc;
                pc = 0x34u;
                break;
            case 0x34u:
                if (idx >= 16u) {
                    pc = 0x5Du;
                    break;
                }
                {
                    uint32_t b = meta[idx];
                    x ^= b << ((idx & 3u) * 8u);
                    x = rol32(x + 0x9E3779B9u + idx * 0x045D9F3Bu,
                              (b & 7u) + 3u);
                    idx++;
                    pc = ((x ^ idx) & 3u) == 0u ? 0x49u : 0x34u;
                }
                break;
            case 0x49u:
                x ^= rol32(seed + idx + 0x165667B1u, idx & 15u);
                pc = 0x34u;
                break;
            case 0x5Du:
                x ^= x >> 16;
                x *= 0x7FEB352Du;
                x ^= x >> 15;
                x *= 0x846CA68Bu;
                x ^= x >> 16;
                return x;
            default:
                pc = 0x5Du;
                break;
        }
    }
}


static uint8_t mba_gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(0u - (b & 1u));
        r ^= a & mask;
        uint8_t hi = a >> 7;
        a <<= 1;
        a ^= (uint8_t)(0x1Bu & (uint8_t)(0u - hi));
        b >>= 1;
    }
    return r;
}

static uint32_t mba_mds32(uint32_t x) {
    uint8_t a0 = (uint8_t)x, a1 = (uint8_t)(x >> 8);
    uint8_t a2 = (uint8_t)(x >> 16), a3 = (uint8_t)(x >> 24);
    uint8_t b0 = mba_gf_mul(a0, 2) ^ mba_gf_mul(a1, 3) ^ a2 ^ a3;
    uint8_t b1 = a0 ^ mba_gf_mul(a1, 2) ^ mba_gf_mul(a2, 3) ^ a3;
    uint8_t b2 = a0 ^ a1 ^ mba_gf_mul(a2, 2) ^ mba_gf_mul(a3, 3);
    uint8_t b3 = mba_gf_mul(a0, 3) ^ a1 ^ a2 ^ mba_gf_mul(a3, 2);
    return (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
}

static uint32_t mba_inv_mds32(uint32_t x) {
    uint8_t a0 = (uint8_t)x, a1 = (uint8_t)(x >> 8);
    uint8_t a2 = (uint8_t)(x >> 16), a3 = (uint8_t)(x >> 24);
    uint8_t b0 = mba_gf_mul(a0, 0x0e) ^ mba_gf_mul(a1, 0x0b) ^ mba_gf_mul(a2, 0x0d) ^ mba_gf_mul(a3, 0x09);
    uint8_t b1 = mba_gf_mul(a0, 0x09) ^ mba_gf_mul(a1, 0x0e) ^ mba_gf_mul(a2, 0x0b) ^ mba_gf_mul(a3, 0x0d);
    uint8_t b2 = mba_gf_mul(a0, 0x0d) ^ mba_gf_mul(a1, 0x09) ^ mba_gf_mul(a2, 0x0e) ^ mba_gf_mul(a3, 0x0b);
    uint8_t b3 = mba_gf_mul(a0, 0x0b) ^ mba_gf_mul(a1, 0x0d) ^ mba_gf_mul(a2, 0x09) ^ mba_gf_mul(a3, 0x0e);
    return (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
}

static uint32_t mba_fbox32(uint32_t x, uint32_t k) {
    x ^= k;
    x *= 0x45D9F3Bu;
    x ^= x >> 16;
    x *= 0x119DE1F3u;
    x ^= x >> 15;
    return x;
}

static uint32_t mba_feistel32(uint32_t x, uint32_t k) {
    uint16_t l = (uint16_t)x, r = (uint16_t)(x >> 16);
    l ^= (uint16_t)mba_fbox32(r, k);
    r ^= (uint16_t)mba_fbox32(l, k ^ 0x9E37u);
    return (uint32_t)l | ((uint32_t)r << 16);
}

static uint32_t mba_inv_feistel32(uint32_t x, uint32_t k) {
    uint16_t l = (uint16_t)x, r = (uint16_t)(x >> 16);
    r ^= (uint16_t)mba_fbox32(l, k ^ 0x9E37u);
    l ^= (uint16_t)mba_fbox32(r, k);
    return (uint32_t)l | ((uint32_t)r << 16);
}

#define KCTF_MBA_INLINE __attribute__((always_inline)) static inline

KCTF_MBA_INLINE uint32_t mba_barrier32(uint32_t x) {
    __asm__ volatile("" : "+r"(x));
    return x;
}

KCTF_MBA_INLINE uint32_t mba_id32_inline(uint32_t x, uint32_t salt) {
    uint32_t k = mba_barrier32(mba_fbox32(salt ^ x, 0xA5A55A5Au));
    uint32_t y = mba_inv_feistel32(mba_feistel32(x ^ k, salt ^ k), salt ^ k) ^ k;
    y = mba_inv_mds32(mba_mds32(y ^ salt)) ^ salt;
    return mba_barrier32(y);
}

KCTF_MBA_INLINE uint32_t mba_add32_inline_v1(uint32_t a, uint32_t b, uint32_t salt) {
    uint32_t s = a, c = b;
    for (int i = 0; i < 32; i++) {
        uint32_t ns = s ^ c;
        c = (s & c) << 1;
        s = ns;
    }
    return mba_id32_inline(s, salt ^ 0x6C8E9CF5u);
}

KCTF_MBA_INLINE uint32_t mba_xor32_inline_v1(uint32_t a, uint32_t b, uint32_t salt) {
    uint32_t ma = mba_barrier32(mba_fbox32(a ^ salt, 0xC2B2AE35u));
    uint32_t mb = mba_barrier32(mba_fbox32(b ^ rol32(salt, 7), 0x27D4EB2Fu));
    uint32_t zero = (ma & mb) ^ (ma & ~mb) ^ (~ma & mb) ^ (ma | mb);
    uint32_t t = ((a | b) & ~(a & b)) ^ zero;
    return mba_id32_inline(t, salt ^ ma ^ mb);
}

KCTF_MBA_INLINE uint8_t mba_trunc8_inline_v1(uint32_t x, uint32_t salt) {
    uint32_t hi_noise = mba_fbox32(salt ^ x, 0x165667B1u) & 0xFFFFFF00u;
    uint32_t lo_noise = mba_fbox32(rol32(x, 5) ^ salt, 0x85EBCA77u) & 0x000000FFu;
    uint32_t y = mba_id32_inline((x ^ hi_noise) ^ lo_noise, salt ^ 0x589965CCu);
    return (uint8_t)(y ^ lo_noise);
}

KCTF_MBA_INLINE uint8_t mba_add8_inline_v1(uint32_t a, uint32_t b, uint32_t salt) {
    return mba_trunc8_inline_v1(mba_add32_inline_v1(a, b, salt),
                                salt ^ 0xB492B66Fu);
}

static uint8_t mba_anf_id8(uint8_t x) {
    uint8_t a = (uint8_t)((x << 1) | (x >> 7));
    uint8_t b = (uint8_t)((x << 3) | (x >> 5));
    uint8_t z = (uint8_t)((a & b) ^ (a & (uint8_t)~b) ^ ((uint8_t)~a & b));
    z ^= (uint8_t)(a | b);
    return (uint8_t)(x ^ z);
}

KCTF_MBA_INLINE uint8_t mba_xor8_inline_v1(uint8_t a, uint8_t b, uint32_t salt) {
    return (uint8_t)mba_xor32_inline_v1((uint32_t)mba_anf_id8(a),
                                        (uint32_t)mba_anf_id8(b),
                                        salt ^ 0x3C6EF372u);
}

__attribute__((noinline))
static uint32_t mba_add32(uint32_t a, uint32_t b, uint32_t salt) {
    uint32_t s = a, c = b;
    for (int i = 0; i < 32; i++) {
        uint32_t ns = s ^ c;
        c = (s & c) << 1;
        s = ns;
    }
    return mba_inv_feistel32(mba_feistel32(s, salt), salt);
}

__attribute__((noinline))
static uint32_t mba_xor32(uint32_t a, uint32_t b, uint32_t salt) {
    uint32_t ma = mba_fbox32(salt, 0xA0761D64u);
    uint32_t mb = mba_fbox32(salt ^ 0xE7037ED1u, 0x8EBC6AF1u);
    uint32_t t = mba_inv_mds32(mba_mds32(a ^ ma) ^ mba_mds32(b ^ mb)) ^ ma ^ mb;
    return mba_inv_feistel32(mba_feistel32(t, ma ^ mb), ma ^ mb);
}

static uint8_t mba_xor8(uint8_t a, uint8_t b, uint32_t salt) {
    return (uint8_t)mba_xor32(mba_anf_id8(a), mba_anf_id8(b), salt);
}

__attribute__((noinline))
static uint8_t mba_trunc8_u32(uint32_t x, uint32_t salt) {
    uint32_t hi_noise = mba_fbox32(salt ^ x, 0x589965CCu) & 0xFFFFFF00u;
    uint32_t lo_noise = mba_fbox32(salt, 0x7F4A7C15u) & 0x000000FFu;
    uint32_t y = (x ^ hi_noise) ^ lo_noise;
    y = mba_inv_mds32(mba_mds32(y));
    return (uint8_t)(y ^ lo_noise);
}

__attribute__((noinline))
static uint32_t mba_sub32(uint32_t a, uint32_t b, uint32_t salt) {
    uint32_t d = a, br = b;
    for (int i = 0; i < 32; i++) {
        uint32_t nd = d ^ br;
        br = ((~d) & br) << 1;
        d = nd;
    }
    return mba_inv_feistel32(mba_feistel32(d, salt ^ 0xC3A5C85Cu), salt ^ 0xC3A5C85Cu);
}

static uint8_t mba_sub8(uint8_t a, uint8_t b, uint32_t salt) {
    return mba_trunc8_u32(mba_sub32((uint32_t)a, (uint32_t)b, salt),
                          salt ^ 0xB492B66Fu);
}

__attribute__((noinline))
static uint32_t mba_nonzero_mask32(uint32_t x, uint32_t salt) {
    uint32_t y = mba_xor32(x, 0u, salt);
    uint32_t bit = (y | (0u - y)) >> 31;
    return 0u - bit;
}

static uint8_t mba_nonzero_mask8(uint8_t x, uint32_t salt) {
    uint32_t y = mba_trunc8_u32((uint32_t)x, salt);
    uint32_t bit = (y | (0u - y)) >> 31;
    return (uint8_t)(0u - bit);
}

static uint8_t mba_byte_id8(uint8_t x, uint32_t salt) {
    uint8_t a = (uint8_t)((x << 1) | (x >> 7));
    uint8_t b = (uint8_t)(((uint8_t)(x ^ salt) << 3) | ((uint8_t)(x ^ salt) >> 5));
    uint8_t zero = (uint8_t)((a & b) ^ (a & (uint8_t)~b) ^ ((uint8_t)~a & b) ^ (a | b));
    uint8_t lane = (uint8_t)(x ^ (uint8_t)(salt >> 11));
    zero ^= (uint8_t)(mba_gf_mul(lane, 1u) ^ lane);
    return (uint8_t)(x ^ zero);
}

KCTF_MBA_INLINE uint8_t mba_rol8_inline_v1(uint8_t x, unsigned n, uint32_t salt) {
    n &= 7u;
    uint8_t v = (uint8_t)((x << n) | (x >> ((8u - n) & 7u)));
    uint32_t wide = (uint32_t)v | (mba_fbox32(salt ^ v, 0xBB67AE85u) & 0xFFFFFF00u);
    return mba_byte_id8(mba_trunc8_inline_v1(wide, salt ^ 0xD1B54A32u),
                        salt ^ 0x94D049BBu);
}

static uint8_t mba_rol8(uint8_t x, unsigned n, uint32_t salt) {
    n &= 7u;
    uint8_t v = (uint8_t)((x << n) | (x >> ((8u - n) & 7u)));
    uint32_t wide = (uint32_t)v | (mba_fbox32(salt ^ v, 0xD6E8FEB8u) & 0xFFFFFF00u);
    return mba_byte_id8(mba_trunc8_u32(wide, salt ^ 0xE7037ED1u), salt);
}

static uint32_t mba_ch32(uint32_t x, uint32_t y, uint32_t z, uint32_t salt) {
    uint32_t yy = mba_xor32(y, salt * 0x01010101u, salt ^ 0xB492B66Fu);
    uint32_t zz = mba_xor32(z, rol32(salt, 7), salt ^ 0x9E3779B9u);
    uint32_t out = (x & yy) ^ (~x & zz);
    return mba_xor32(out, (salt ^ rol32(x, 3)) * 0x45D9F3Bu, salt ^ 0x6A09E667u);
}

static uint32_t mba_maj32(uint32_t x, uint32_t y, uint32_t z, uint32_t salt) {
    uint32_t a = mba_xor32(x, rol32(salt, 11), salt ^ 0xBB67AE85u);
    uint32_t b = mba_xor32(y, salt * 0x9E3779B1u, salt ^ 0x3C6EF372u);
    uint32_t c = mba_xor32(z, rol32(salt ^ x, 19), salt ^ 0xA54FF53Au);
    uint32_t out = (a & b) ^ (a & c) ^ (b & c);
    return mba_inv_mds32(mba_mds32(out));
}

static uint32_t mba_poly32(uint32_t x, uint32_t y, uint32_t z, uint32_t salt) {
    uint32_t p = mba_add32(mba_xor32(x, rol32(y, 5), salt ^ 0x510E527Fu),
                           (z | 1u) * (salt | 1u),
                           salt ^ 0x9B05688Cu);
    uint32_t q = (p & rol32(x, 11)) ^ (~p & rol32(mba_xor32(y, z, salt ^ 0x1F83D9ABu), 17));
    q = mba_add32(q, mba_xor32(x, z, salt ^ 0x5BE0CD19u) * 0x119DE1F3u,
                  salt ^ 0xC3A5C85Cu);
    return mba_inv_feistel32(mba_feistel32(q, salt ^ p), salt ^ p);
}

static void reset_scheme_a_state(void) {
    extern uint8_t  sbox_shipped[256];
    extern uint32_t xtea_delta;
    extern uint32_t round_constants[32];
    extern uint8_t  step2_amount;
    extern uint32_t step3_param;
    extern uint8_t  step3_bits;
    extern uint32_t dispatch_table[4];

    secure_bzero(sbox_shipped, 256);
    xtea_delta = 0x9E3779B9u;
    secure_bzero(round_constants, sizeof(uint32_t) * 32);
    step2_amount = 0;
    step3_param = 0;
    step3_bits = 16;
    secure_bzero(dispatch_table, sizeof(uint32_t) * 4);
}


static uint8_t derive_scheme_a_share(void) {
    extern uint8_t  sbox_shipped[256];
    extern uint32_t round_constants[32];
    extern uint8_t  step2_amount;
    extern uint32_t step3_param;
    extern uint32_t dispatch_table[4];

    uint32_t x = mba_xor32(dispatch_table[0], round_constants[0], 0xA5A55A5Au);
    x = mba_xor32(x, step3_param, x ^ 0x6C8E9CF5u);
    uint32_t y = mba_xor32((uint32_t)step2_amount << 24,
                           (uint32_t)sbox_shipped[0] * 0x01010101u,
                           x ^ 0xB4B82E39u);
    x = mba_xor32(x, y, 0xC2B2AE35u);
    x = mba_xor32(x, x >> 16, y ^ 0x27D4EB2Fu);
    x *= 0x45D9F3Bu;
    x = mba_xor32(x, x >> 15, y ^ 0x165667B1u);
    uint8_t raw_share = (uint8_t)mba_xor32(x, x >> 8, 0x85EBCA77u);
    return mba_xor8(raw_share, SCHEME_A_SHARE_TUNE, 0xD6E8FEB8u);
}

static uint8_t derive_material_share(const uint8_t *material) {
    uint8_t r = mba_rol8(material[95], 1u, 0x589965CCu);
    uint8_t x = mba_xor8(material[60], material[80], 0xD6E8FEB8u);
    x = mba_xor8(x, r, 0xA0761D64u);
    return mba_xor8(x, 0x5Du, 0xE7037ED1u);
}

static void apply_cross_mask(uint8_t *buf, uint8_t share, uint8_t domain) {
    uint8_t x = mba_xor8(share, domain, 0x94D049BBu);
    for (int i = 0; i < STATE_LEN; i++) {
        uint32_t step = mba_add32((uint32_t)x * 0x3Du, (uint32_t)(0x71u + i * 0x13u), 0x2545F491u ^ (uint32_t)i);
        x = mba_trunc8_u32(step, step ^ 0x165667B1u);
        uint8_t fold = mba_trunc8_u32(mba_xor32((uint32_t)x, (uint32_t)(x >> 3), step ^ 0x9E3779B9u),
                                      step ^ 0x85EBCA77u);
        buf[i] = mba_xor8(buf[i], fold, step);
    }
}

static uint8_t rol8(uint8_t x, unsigned n) {
    return mba_rol8(x, n, 0x7F4A7C15u ^ (uint32_t)n);
}

static void const_xor_load_split(uint8_t out[STATE_LEN],
                                 const volatile uint8_t s0[STATE_LEN],
                                 const volatile uint8_t s1[STATE_LEN],
                                 uint8_t domain) {
    uint8_t tmp[STATE_LEN];
    for (int i = 0; i < STATE_LEN; i++) {
        uint8_t lane = mba_rol8((uint8_t)s1[(i * 7 + 3) & 0x0F],
                                (unsigned)(i + domain),
                                0x589965CCu ^ (uint32_t)(domain + i));
        tmp[i] = mba_xor8((uint8_t)s0[i], mba_xor8(lane, (uint8_t)(domain + i * 0x31u), 0xD6E8FEB8u ^ (uint32_t)i), 0xA0761D64u ^ (uint32_t)i);
    }
    const_xor_load(out, tmp, STATE_LEN);
    secure_bzero(tmp, sizeof(tmp));
}

static void decode_flag_a(const uint8_t *flagA, const uint8_t *soKey, uint8_t out[FLAG_HALF]) {
    static const uint8_t perm[FLAG_HALF] = {
        7, 2, 19, 0, 14, 23, 5, 11, 21, 3, 17, 8, 24,
        1, 12, 6, 20, 10, 4, 22, 15, 9, 18, 13, 16
    };
    uint8_t prev = mba_xor8(soKey[7], 0xC3u, 0xBADC0DEu);
    for (int i = 0; i < FLAG_HALF; i++) {
        uint32_t salt = 0x6D2B79F5u ^ (uint32_t)(i * 0x45D9F3Bu);
        uint8_t mix_base = (uint8_t)mba_add32(prev, (uint32_t)(i * 0x31u), salt);
        mix_base = mba_trunc8_u32(mba_add32(mix_base, soKey[(i * 7 + 1) & 0x0F], salt ^ 0xA0761D64u),
                                  salt ^ 0x510E527Fu);
        uint8_t mix = mba_rol8(mix_base, (unsigned)i, salt ^ 0x9B05688Cu);
        uint8_t shifted = mba_sub8(flagA[perm[i]], mix, salt ^ 0xE7037ED1u);
        out[i] = mba_xor8(mba_byte_id8(shifted, salt ^ 0x1F83D9ABu),
                          soKey[(i * 5 + 3) & 0x0F],
                          salt ^ 0x8EBC6AF1u);
        uint8_t tail = mba_trunc8_u32(0x5Au + (uint32_t)i * 0x23u, salt ^ 0x5BE0CD19u);
        prev = mba_xor8(mba_trunc8_u32(mba_add32(out[i], mix, salt ^ 0xD1B54A32u), salt ^ 0xC3A5C85Cu),
                        tail, salt ^ 0x94D049BBu);
    }
}

static volatile const uint8_t FAKE_MATERIAL_HINT_ENC[16] = {
    0xB2, 0x71, 0x0E, 0x5D, 0x93, 0x42, 0xC8, 0x1F,
    0x2A, 0xE4, 0x77, 0x90, 0x5C, 0x39, 0xA6, 0xD1
};

static uint8_t fake_material_decoy(const uint8_t *flagB, uint8_t a_share,
                                   uint32_t lane_ctx) {
    uint8_t material[32];
    expand_key_material(flagB, material, sizeof(material));

    uint8_t hint[16];
    const_xor_load(hint, (const uint8_t *)FAKE_MATERIAL_HINT_ENC, 16);
    for (int i = 0; i < 16; i++) {
        uint8_t ctx_byte = mba_trunc8_inline_v1(lane_ctx >> ((i & 3) * 8),
                                                0x6A09E667u ^ (uint32_t)i);
        hint[i] = mba_xor8_inline_v1(hint[i],
                                     mba_add8_inline_v1(a_share ^ ctx_byte,
                                                        i * 0x2Bu,
                                                        0xD1B54A32u),
                                     0x133111EBu ^ (uint32_t)i);
    }

    uint8_t syndrome = mba_xor8_inline_v1(mba_trunc8_inline_v1((uint32_t)a_share + 0x6Du, 0x7F4A7C15u),
                                          material[7] ^ mba_trunc8_inline_v1(lane_ctx, 0x510E527Fu),
                                          0x7F4A7C15u);
    for (int i = 0; i < 16; i++) {
        uint8_t lane = material[8 + ((i * 5 + 3) & 0x0F)];
        uint8_t d = mba_xor8_inline_v1(lane, hint[i], 0x7F4A7C15u ^ (uint32_t)i);
        uint8_t echo = mba_rol8_inline_v1(material[16 + ((i * 3 + 1) & 0x0F)],
                                          (unsigned)(i + 1),
                                          0x589965CCu ^ (uint32_t)i);
        d = mba_xor8_inline_v1(d, echo, 0x2545F491u ^ (uint32_t)(i * 0x3Du));
        d = mba_xor8_inline_v1(d,
                               mba_trunc8_inline_v1(lane_ctx >> (((i + 1) & 3) * 8),
                                                    0x94D049BBu ^ (uint32_t)i),
                               0xBB67AE85u ^ (uint32_t)i);
        uint8_t addend = mba_trunc8_inline_v1((uint32_t)d + (uint32_t)i * 0x17u,
                                              0x9E3779B9u ^ (uint32_t)i);
        syndrome = mba_add8_inline_v1(syndrome, addend, 0x9E3779B9u ^ (uint32_t)i);
        syndrome = mba_rol8_inline_v1(syndrome, (unsigned)((i & 3) + 1), 0x165667B1u ^ (uint32_t)i);
        uint8_t mix = mba_trunc8_inline_v1((uint32_t)d * 0x3Du + (uint32_t)i,
                                           0x27D4EB2Fu ^ (uint32_t)(i * 0x101u));
        syndrome = mba_xor8_inline_v1(syndrome, mix, 0xC2B2AE35u ^ (uint32_t)(i * 0x101u));
        lane_ctx = mba_add32_inline_v1(lane_ctx ^ ((uint32_t)mix << ((i & 3) * 8)),
                                       (uint32_t)d * 0x01010101u,
                                       0xA0761D64u ^ (uint32_t)i);
        lane_ctx = rol32(lane_ctx, (unsigned)((mix & 7u) + 3u));
    }

    secure_bzero(material, sizeof(material));
    secure_bzero(hint, sizeof(hint));
    return syndrome;
}

static uint8_t jni_token_key(uint32_t salt, unsigned i) {
    uint32_t x = salt ^ (i * 0x045D9F3Bu + 0xA5A5A5A5u);
    x ^= x >> 15;
    x *= 0x2C1B3C6Du;
    x ^= x >> 12;
    return (uint8_t)(x ^ (x >> 8) ^ (0x31u + i * 0x17u));
}

static void decode_jni_token(char *out, const volatile uint8_t *enc,
                             unsigned len, uint32_t salt) {
    for (unsigned i = 0; i < len; i++)
        out[i] = (char)(enc[i] ^ jni_token_key(salt, i));
    out[len] = '\0';
}

static jfieldID java_archive_shadow_slot(JNIEnv *env, jclass clazz, uint32_t lane) {
    static const volatile uint8_t field_enc[] = { 0xDFu };
    static const volatile uint8_t sig_enc[] = { 0xF2u };
    char field_name[2];
    char field_sig[2];
    uint32_t lane_mask = (lane ^ lane) & 0x7F4A7C15u;
    decode_jni_token(field_name, field_enc, 1, 0xA91D3B05u ^ lane_mask);
    decode_jni_token(field_sig, sig_enc, 1, 0xD046E405u ^ lane_mask);
    jfieldID fid = (*env)->GetStaticFieldID(env, clazz, field_name, field_sig);
    secure_bzero(field_name, sizeof(field_name));
    secure_bzero(field_sig, sizeof(field_sig));
    if (!fid && (*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);
    return fid;
}

static jsize collect_java_archive_meta(JNIEnv *env, jobject obj, uint8_t *meta,
                                       jsize meta_cap, uint32_t *profile_seed) {
    static const volatile uint8_t method_enc[] = { 0x3Fu };
    static const volatile uint8_t sig_enc[] = { 0xE2u, 0xB7u, 0x19u, 0x0Du };
    char method_name[2];
    char method_sig[5];
    decode_jni_token(method_name, method_enc, 1, 0x4D5A6B7Cu);
    decode_jni_token(method_sig, sig_enc, 4, 0x9E3779B9u);

    jclass clazz = (*env)->GetObjectClass(env, obj);
    jmethodID mid = clazz ? (*env)->GetMethodID(env, clazz, method_name, method_sig) : NULL;
    if (!mid && (*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    uint32_t seed = JAVA_PROFILE_SEED_DEFAULT;
    uint32_t previous = JAVA_PROFILE_SEED_DEFAULT;
    jfieldID shadow = NULL;
    uint32_t lane = java_profile_runtime_seed();
    uint32_t pc = 0x42u;

    while (pc != 0x7Eu) {
        switch (pc) {
            case 0x42u:
                shadow = clazz ? java_archive_shadow_slot(env, clazz, lane) : NULL;
                pc = shadow ? 0x19u : 0x53u;
                break;
            case 0x19u:
                previous = (uint32_t)(*env)->GetStaticIntField(env, clazz, shadow);
                if ((*env)->ExceptionCheck(env)) {
                    (*env)->ExceptionClear(env);
                    shadow = NULL;
                    pc = 0x53u;
                    break;
                }
                seed = lane ^ ((lane ^ lane) & 0xC3A5C85Cu);
                (*env)->SetStaticIntField(env, clazz, shadow, (jint)seed);
                if ((*env)->ExceptionCheck(env)) {
                    (*env)->ExceptionClear(env);
                    shadow = NULL;
                    seed = JAVA_PROFILE_SEED_DEFAULT;
                }
                pc = 0x53u;
                break;
            default:
                pc = 0x7Eu;
                break;
        }
    }

    jbyteArray jarr = NULL;
    if (mid)
        jarr = (jbyteArray)(*env)->CallObjectMethod(env, obj, mid);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        jarr = NULL;
    }

    if (shadow) {
        (*env)->SetStaticIntField(env, clazz, shadow, (jint)previous);
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
    }

    secure_bzero(method_name, sizeof(method_name));
    secure_bzero(method_sig, sizeof(method_sig));

    jsize len = jarr ? (*env)->GetArrayLength(env, jarr) : 0;
    jsize copy_len = (len < meta_cap) ? len : meta_cap;
    if (copy_len > 0)
        (*env)->GetByteArrayRegion(env, jarr, 0, copy_len, (jbyte *)meta);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        len = 0;
    }
    if (jarr)
        (*env)->DeleteLocalRef(env, jarr);
    if (clazz)
        (*env)->DeleteLocalRef(env, clazz);
    if (profile_seed)
        *profile_seed = seed;
    return len;
}

/* ── JNI 回调获取 soKey ──────────────────────────────────── */
static void fetch_sokey(JNIEnv *env, jobject obj, uint8_t out[SOKEY_LEN]) {
    (void)kctf_guard_anchor();
    uint8_t meta[32] = {0};
    uint32_t profile_seed = JAVA_PROFILE_SEED_DEFAULT;
    g_java_archive_profile_delta = 0xD17F00D5u;
    jsize len = collect_java_archive_meta(env, obj, meta, (jsize)sizeof(meta), &profile_seed);
    memcpy(out, meta, SOKEY_LEN);
    for (int i = 0; i < SOKEY_LEN; i++)
        out[i] ^= sokey_share_mask(i);

    if (len >= 32) {
        uint32_t profile = load_le32(meta + 28);
        uint32_t expected_profile = java_archive_profile_word(meta, profile_seed);
        uint32_t profile_diff = mba_xor32(profile, expected_profile, 0x8EBC6AF1u);
        uint32_t profile_poison = kctf_bait_zero_mask(0x6B32u,
            profile ^ expected_profile ^ load_le32(out) ^ load_le32(meta + 16));
        g_java_archive_profile_delta = profile_diff ^ profile_poison;
    }

    if (len >= 28) {
        uint32_t apk_crc  = load_le32(meta + 16);
        uint32_t text_off = load_le32(meta + 20);
        uint32_t text_len = load_le32(meta + 24);
        uint32_t mem_crc  = kctf_runtime_text_crc(text_off, text_len);
        uint32_t diff = apk_crc ^ mem_crc;
        uint32_t poison = mba_nonzero_mask32(diff, 0x510E527Fu) & 0x9E3779B9u;
        for (int i = 0; i < SOKEY_LEN; i++)
            out[i] ^= (uint8_t)(poison >> ((i & 3) * 8));
    } else {
        for (int i = 0; i < SOKEY_LEN; i++)
            out[i] ^= (uint8_t)(0xA5u + i * 17u);
    }
    secure_bzero(meta, sizeof(meta));
}

/* ── 方案 A 内部验证（不导出为 JNI）────────────────────── */
static int verify_scheme_a(const uint8_t *flagA, const uint8_t *soKey, uint8_t material_share, uint8_t *out_a_share) {
    reset_scheme_a_state();

    uint8_t plainA[FLAG_HALF];
    decode_flag_a(flagA, soKey, plainA);

    /* 修复链 */
    repair_cfg(plainA, soKey);

    extern uint32_t dispatch_table[4];
    uint8_t cfg_dep = (uint8_t)(dispatch_table[0] & 0xFFu);
    repair_sbox(plainA, cfg_dep);

    extern uint8_t sbox_shipped[256];
    uint8_t sbox_first = sbox_shipped[0];
    repair_constants(plainA, sbox_first);

    extern uint32_t round_constants[32];
    uint8_t rc_high4 = (uint8_t)(round_constants[0] >> 28);
    repair_semantics(plainA, rc_high4);

    uint8_t a_share = derive_scheme_a_share();
    if (out_a_share)
        *out_a_share = a_share;

    /* 执行 BB0~BB7 */
    uint32_t state32[4] = {0, 0, 0, 0};
    core_compute(state32);

    uint8_t final_state[STATE_LEN];
    for (int i = 0; i < 4; i++) {
        final_state[i*4+0] = (uint8_t)(state32[i]      );
        final_state[i*4+1] = (uint8_t)(state32[i] >>  8);
        final_state[i*4+2] = (uint8_t)(state32[i] >> 16);
        final_state[i*4+3] = (uint8_t)(state32[i] >> 24);
    }

    uint8_t expected[STATE_LEN];
    const_xor_load_split(expected, ENC_EXPECTED_STATE_A_S0, ENC_EXPECTED_STATE_A_S1, 0xA7u);
    for (int i = 0; i < STATE_LEN; i++)
        expected[i] ^= soKey[i];
    uint32_t bait_z_a = kctf_bait_zero_mask(0x6A01u,
        load_le32(expected) ^ load_le32(plainA) ^ (uint32_t)material_share);
    for (int i = 0; i < 4; i++)
        expected[i] ^= (uint8_t)(bait_z_a >> (i * 8));
    apply_cross_mask(expected, material_share, 0xA1u);

    volatile uint8_t diff = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff |= mba_xor8(final_state[i], expected[i], 0x94D049BBu ^ (uint32_t)i);

    secure_bzero(final_state, sizeof(final_state));
    secure_bzero(expected, sizeof(expected));
    secure_bzero(state32, sizeof(state32));
    secure_bzero(plainA, sizeof(plainA));
    return (diff == 0) ? 1 : 0;
}

/* ── 密钥派生辅助函数（诱导选手 hook）─────────────────────
 * 这些函数在正确路径中被调用，返回值参与最终验证。
 * 选手看到函数名会想 hook 它们获取中间密钥，
 * 但 hook 行为会触发蜜罐 F（inline hook 检测）。
 * 函数内部逻辑故意复杂化，让选手觉得"hook 比逆向更划算"。
 */

/* 从 soKey 派生 session token — 看起来像"解密主密钥" */
static void get_session_token(const uint8_t *soKey, const uint8_t *material,
                              uint8_t out[16]) {
    /* HMAC-like 结构（实际是简单 XOR + 旋转，但看起来很复杂） */
    uint32_t state[4];
    for (int i = 0; i < 4; i++)
        state[i] = ((uint32_t)soKey[i*4] << 24) | ((uint32_t)soKey[i*4+1] << 16) |
                   ((uint32_t)soKey[i*4+2] << 8) | (uint32_t)soKey[i*4+3];

    /* 8 轮"密钥调度"（实际只是混合 material） */
    for (int r = 0; r < 8; r++) {
        uint32_t m = ((uint32_t)material[r*4] << 24) | ((uint32_t)material[r*4+1] << 16) |
                     ((uint32_t)material[r*4+2] << 8) | (uint32_t)material[r*4+3];
        state[r & 3] ^= m;
        state[(r+1) & 3] += state[r & 3];
        state[(r+2) & 3] ^= (state[(r+1) & 3] >> 7) | (state[(r+1) & 3] << 25);
    }

    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(state[i] >> 24);
        out[i*4+1] = (uint8_t)(state[i] >> 16);
        out[i*4+2] = (uint8_t)(state[i] >> 8);
        out[i*4+3] = (uint8_t)(state[i]);
    }
}

/* 从 session token 派生 verification key — 看起来像"最终比对密钥" */
static void derive_verification_key(const uint8_t *token, const uint8_t *iv,
                                    uint8_t out[16]) {
    /* "AES-like key whitening"（实际是 XOR + 字节旋转） */
    for (int i = 0; i < 16; i++)
        out[i] = token[i] ^ iv[i] ^ token[(i + 7) & 0xF];

    /* "Key stretching"（4 轮自混合） */
    for (int r = 0; r < 4; r++) {
        uint8_t tmp = out[0];
        for (int i = 0; i < 15; i++)
            out[i] = out[i] ^ out[i+1] ^ (uint8_t)(r * 0x37 + i);
        out[15] = out[15] ^ tmp ^ (uint8_t)(r * 0x37 + 15);
    }
}

static void encode_oracle_material_head(const uint8_t *material, const uint8_t *seeds,
                                        const uint8_t *soKey, uint8_t a_share,
                                        uint8_t out[8]) {
    uint8_t fb = mba_xor8_inline_v1(a_share, soKey[2], 0x6A09E667u);
    for (int i = 0; i < 8; i++) {
        uint32_t salt = 0xBB67AE85u ^ (uint32_t)(i * 0x3C6EF372u);
        uint8_t x = mba_xor8_inline_v1(material[i], seeds[(i * 5 + 3) & 0x0F], salt);
        x = mba_xor8_inline_v1(x, soKey[(i * 7 + 9) & 0x0F], salt ^ 0xA54FF53Au);
        uint8_t add_lane = mba_trunc8_inline_v1((uint32_t)i * 0x2Du + fb, salt ^ 0x510E527Fu);
        uint8_t add = mba_add8_inline_v1(a_share, add_lane, salt ^ 0x510E527Fu);
        x = mba_add8_inline_v1(x, add, salt ^ 0x9B05688Cu);
        uint8_t lane_in = mba_trunc8_inline_v1((uint32_t)seeds[(i + 11) & 0x0F] + fb,
                                               salt ^ 0x5BE0CD19u);
        uint8_t lane = mba_rol8_inline_v1(lane_in, (unsigned)(i + 1), salt ^ 0xC3A5C85Cu);
        out[i] = mba_xor8_inline_v1(x, lane, salt ^ 0x1F83D9ABu);
        uint8_t fb_tail = mba_trunc8_inline_v1((uint32_t)material[(i + 3) & 7] + 0x5Au + (uint32_t)i,
                                               salt ^ 0x27D4EB2Fu);
        fb = mba_xor8_inline_v1(out[i], fb_tail, salt ^ 0x5BE0CD19u);
    }
}

/*
 * Material lane compressor.
 *
 * material[8:16] is intentionally not exposed by the oracle.  Before it is
 * checked by the 32-bit mid tag, the bytes are carried through wider lanes and
 * projected back to bytes only at the end of each small step.  This keeps the
 * native dataflow looking like a compact key-schedule fold, while a bit-vector
 * model has to preserve the exact order of byte extraction, carry/borrow
 * propagation, variable rotates, and final truncation.
 */
static uint8_t material_project_byte(uint32_t x, unsigned lane, uint32_t salt) {
    uint32_t shifted = x >> ((lane & 3u) * 8u);
    uint32_t carrier = shifted ^ (mba_fbox32(salt ^ shifted, 0x589965CCu) & 0xFFFFFF00u);
    return mba_trunc8_inline_v1(carrier, salt ^ 0x7F4A7C15u);
}

static uint32_t material_compress_lane32(uint32_t x, uint32_t y, uint32_t z,
                                         uint32_t salt, unsigned round) {
    uint8_t lanes[4] = {0, 0, 0, 0};
    uint32_t carry = mba_xor32_inline_v1(rol32(x, (round + 3u) & 31u),
                                         y ^ salt,
                                         salt ^ 0xB492B66Fu);

    for (unsigned i = 0; i < 4; i++) {
        uint8_t xb = material_project_byte(x, i, salt ^ (uint32_t)(i * 0x45D9F3Bu));
        uint8_t yb = material_project_byte(y, i + 1u, salt ^ (uint32_t)(i * 0x119DE1F3u));
        uint8_t zb = material_project_byte(z, i + 2u, salt ^ (uint32_t)(i * 0x9E3779B1u));
        uint8_t cb = material_project_byte(carry, i, salt ^ (uint32_t)(i * 0x6D2B79F5u));

        uint32_t sum32 = mba_add32_inline_v1((uint32_t)xb,
                                             (uint32_t)mba_xor8_inline_v1(yb, cb, salt ^ 0xA0761D64u),
                                             salt ^ (uint32_t)(i * 0x2545F491u));
        uint8_t sum = mba_trunc8_inline_v1(sum32, salt ^ 0xD1B54A32u ^ i);
        uint8_t tail = mba_trunc8_inline_v1((uint32_t)zb + round * 0x11u + i,
                                            salt ^ 0x94D049BBu ^ (uint32_t)(i * 0x101u));
        uint8_t diff = mba_sub8(sum, tail, salt ^ 0xC2B2AE35u ^ i);
        uint8_t rc = (uint8_t)((xb ^ zb ^ cb ^ (uint8_t)salt ^ (uint8_t)round) & 7u);
        uint8_t rot = mba_rol8_inline_v1(diff, rc, salt ^ 0x165667B1u ^ (uint32_t)i);

        uint32_t gate = mba_ch32(x ^ carry,
                                 y ^ rol32(salt, i + 1u),
                                 z ^ rol32(carry, i + 3u),
                                 salt ^ 0x27D4EB2Fu ^ i);
        uint8_t gate_lane = material_project_byte(gate, i, salt ^ 0x85EBCA77u);
        uint8_t out_lane = mba_xor8_inline_v1(rot, gate_lane, salt ^ 0xE7037ED1u ^ i);
        unsigned pos = (i * 3u + round) & 3u;
        lanes[pos] = out_lane;

        uint32_t lane_word = (uint32_t)out_lane << ((pos & 3u) * 8u);
        carry = mba_add32_inline_v1(carry ^ lane_word,
                                    sum32 ^ ((uint32_t)zb << (((3u - i) & 3u) * 8u)),
                                    salt ^ 0x8EBC6AF1u ^ (uint32_t)(i * 0x3Du));
        carry = rol32(carry, (unsigned)((rc + i + 1u) & 31u));
    }

    uint32_t packed = (uint32_t)lanes[0]
                    | ((uint32_t)lanes[1] << 8)
                    | ((uint32_t)lanes[2] << 16)
                    | ((uint32_t)lanes[3] << 24);
    uint32_t mixed = mba_mds32(packed ^ salt);
    mixed = mba_xor32_inline_v1(mixed,
                                rol32(carry, (unsigned)(((x ^ y ^ salt) & 7u) + 5u)),
                                salt ^ 0x510E527Fu);
    return mba_inv_feistel32(mba_feistel32(mixed, carry ^ salt), carry ^ salt);
}

/*
 * Cross-segment lane context.
 *
 * The oracle head check consumes encoded material[0:8], while the mid tag and
 * fake syndrome consume material[8:16].  This context ties those three checks
 * together: the hidden bytes, the encoded oracle projection, seeds, and soKey
 * all update one small scheduler word before any final comparison happens.
 */
static uint32_t derive_lane_context(const uint8_t *material,
                                    const uint8_t encoded_head[8],
                                    const uint8_t *seeds,
                                    const uint8_t *soKey,
                                    uint8_t a_share) {
    uint32_t ctx = mba_xor32_inline_v1(load_le32(material + 8),
                                       rol32(load_le32(material + 12), 7),
                                       0xD6E8FEB8u);
    ctx = mba_xor32_inline_v1(ctx,
                              load_le32(seeds) ^ ((uint32_t)a_share * 0x01010101u),
                              0xA0761D64u);

    for (int i = 0; i < 8; i++) {
        uint32_t salt = 0x3A5C742Eu ^ (uint32_t)(i * 0x45D9F3Bu) ^ rol32(ctx, i + 1);
        uint8_t hidden = material[8 + i];
        uint8_t enc = encoded_head[(i * 5 + 1) & 7];
        uint8_t seed_lane = seeds[(i * 3 + 2) & 0x0F];
        uint8_t key_lane = soKey[(i * 7 + 4) & 0x0F];
        uint8_t ctx_lane = mba_trunc8_inline_v1(ctx >> ((i & 3) * 8), salt ^ 0x510E527Fu);

        uint8_t braid = mba_xor8_inline_v1(hidden, enc, salt ^ 0x9E3779B9u);
        braid = mba_sub8(braid,
                         mba_xor8_inline_v1(seed_lane, key_lane, salt ^ 0xC2B2AE35u),
                         salt ^ 0x165667B1u);
        braid = mba_add8_inline_v1(braid, ctx_lane ^ a_share, salt ^ 0x27D4EB2Fu);
        uint8_t rc = (uint8_t)((braid ^ hidden ^ seed_lane ^ ctx_lane) & 7u);
        braid = mba_rol8_inline_v1(braid, rc, salt ^ 0xE7037ED1u);

        uint32_t fold = material_compress_lane32(load_le32(material + 8),
                                                 load_le32(material),
                                                 load_le32(seeds + ((i & 3) * 4)),
                                                 salt ^ (uint32_t)braid,
                                                 (unsigned)(i + 1));
        uint32_t lane_word = (uint32_t)braid << ((i & 3) * 8);
        ctx = mba_add32_inline_v1(ctx ^ lane_word,
                                  fold ^ ((uint32_t)enc * 0x01010101u),
                                  salt ^ 0x8EBC6AF1u);
        ctx = rol32(ctx, (unsigned)((rc + i + 5) & 31u));
    }

    uint32_t tail = material_compress_lane32(load_le32(material + 12),
                                             load_le32(seeds + 4),
                                             load_le32(soKey),
                                             ctx ^ 0xB492B66Fu,
                                             9u);
    return mba_xor32_inline_v1(ctx, tail, 0x6A09E667u);
}

static uint64_t derive_material_lane_hint_mask(const uint8_t *material,
                                               const uint8_t *seeds,
                                               const uint8_t *soKey,
                                               uint8_t a_share,
                                               uint32_t lane_ctx) {
    uint64_t x = ((uint64_t)load_le32(seeds + 8) << 32) | load_le32(soKey + 4);
    x ^= ((uint64_t)load_le32(seeds) << 9) | ((uint64_t)load_le32(soKey) >> 3);
    x ^= (uint64_t)load_le32(material) << 16;
    x ^= (uint64_t)load_le32(material + 4) << 1;
    x ^= (uint64_t)lane_ctx * 0x9E3779B185EBCA87ULL;
    x ^= (uint64_t)a_share * 0x0101010101010101ULL;
    x ^= x >> 33;
    x *= 0xFF51AFD7ED558CCDULL;
    x ^= x >> 33;
    x *= 0xC4CEB9FE1A85EC53ULL;
    x ^= x >> 33;
    return x;
}

#define MATERIAL_LANE_HINT_MASK 0x00003FFFFFFFFFFFULL

typedef uint64_t (*material_lane_stage_t)(uint64_t, uint64_t, uint32_t, uint8_t);
static material_lane_stage_t volatile g_material_lane_stage = kctf_honey_q46_bridge;

static uint64_t material_lane_zero64(uint64_t lane, uint64_t mask,
                                     uint32_t lane_ctx, uint32_t tag) {
    uint32_t z0 = kctf_bait_zero_mask((uint16_t)tag,
        (uint32_t)lane ^ rol32((uint32_t)(lane >> 32), 7) ^
        (uint32_t)mask ^ lane_ctx);
    uint32_t z1 = mba_xor32_inline_v1(z0, z0, tag ^ 0x6D46B102u);
    uint32_t z2 = mba_add32_inline_v1(z1, z0 ^ z1, tag ^ 0x94D049BBu);
    uint32_t nl = mba_ch32((uint32_t)lane ^ z0,
                           (uint32_t)(mask >> 32) ^ z1,
                           lane_ctx ^ z2,
                           tag ^ 0xD046E405u);
    uint32_t zn = mba_xor32_inline_v1(nl, nl, tag ^ 0x1F83D9ABu);
    return (((uint64_t)(z2 ^ zn) << 32) |
            (uint64_t)mba_xor32_inline_v1(z0 ^ zn, z2, tag ^ 0x510E527Fu));
}

static uint64_t material_lane_shadow_linear(uint64_t lane, uint64_t mask,
                                            uint32_t lane_ctx, uint8_t a_share) {
    uint64_t out = 0;
    uint32_t carry = mba_xor32_inline_v1((uint32_t)lane,
                                         (uint32_t)(mask >> 32) ^ lane_ctx,
                                         0xD046C203u);
    for (unsigned i = 0; i < 50u; i++) {
        unsigned pos = (i * 13u + 7u) & 63u;
        unsigned mpos = (i * 9u + 5u) & 63u;
        uint64_t bit = ((lane >> pos) ^ (mask >> mpos) ^
                        (uint64_t)(i * 0x9Eu + 0x37u)) & 1ULL;
        carry = mba_add32_inline_v1(carry ^ (uint32_t)(bit << (i & 31u)),
                                    (uint32_t)(lane >> ((i * 5u) & 31u)) ^
                                    ((uint32_t)a_share << ((i & 3u) * 8u)),
                                    0x6D46D304u ^ i);
        out |= bit << i;
    }
    return (out ^ ((uint64_t)(carry ^ carry) << 14)) & 0x0003FFFFFFFFFFFFULL;
}

static uint64_t derive_material_lane_hint(const uint8_t *material,
                                          const uint8_t *seeds,
                                          const uint8_t *soKey,
                                          uint8_t a_share,
                                          uint32_t lane_ctx) {
    uint64_t lane = load_le64(material + 8);
    uint64_t mask = derive_material_lane_hint_mask(material, seeds, soKey, a_share, lane_ctx);
    KCTF_REAL_BR_FALSE_BAIT_CSEL(0xE946u,
        (uint32_t)lane ^ (uint32_t)(lane >> 32) ^
        (uint32_t)mask ^ lane_ctx ^ ((uint32_t)a_share << 24),
        kctf_honey_q46_bridge);

    uint64_t z0 = material_lane_zero64(lane, mask, lane_ctx, 0x6B460001u);
    uint64_t z1 = material_lane_zero64(mask ^ z0, lane, lane_ctx ^ (uint32_t)z0, 0x6B460002u);
    uint32_t ctx_in = mba_xor32_inline_v1(lane_ctx ^ (uint32_t)z0,
                                          (uint32_t)z0,
                                          0x6B46A001u);
    uint8_t share_in = mba_xor8_inline_v1(a_share ^ (uint8_t)z1,
                                          (uint8_t)z1,
                                          0x6B46B102u);
    uint64_t lane_in = lane ^ z0 ^ rol64(z1, (ctx_in ^ a_share) & 63u);
    uint64_t mask_in = mask ^ z1 ^ rol64(z0, (lane_ctx ^ share_in) & 63u);
    material_lane_stage_t stage = g_material_lane_stage;
    uint64_t q46 = stage(lane_in, mask_in, ctx_in, share_in);
    uint64_t shadow = material_lane_shadow_linear(lane, mask, lane_ctx, a_share);
    uint64_t blend = material_lane_zero64(q46 ^ shadow, mask, ctx_in, 0x6B460003u) &
                     MATERIAL_LANE_HINT_MASK;
    uint64_t merged = (q46 & ~blend) | (shadow & blend);
    return merged & MATERIAL_LANE_HINT_MASK;
}

static uint32_t derive_material_mid_tag(const uint8_t *material, const uint8_t *seeds,
                                        const uint8_t *soKey, uint8_t a_share,
                                        uint32_t lane_ctx) {
    uint32_t a = mba_xor32_inline_v1(load_le32(material + 8),
                                     load_le32(soKey) ^ rol32(lane_ctx, 5),
                                     0xD1B54A32u);
    uint32_t b = mba_xor32_inline_v1(load_le32(material + 12),
                                     load_le32(soKey + 4) ^ rol32(lane_ctx, 13),
                                     0x94D049BBu);
    uint32_t c = mba_xor32(load_le32(material),
                           load_le32(seeds + 8) ^ lane_ctx,
                           0x2545F491u);
    uint32_t d = mba_xor32(load_le32(material + 4),
                           load_le32(seeds + 12) ^ rol32(lane_ctx, 21),
                           0x9E3779B9u);

    for (int r = 0; r < 5; r++) {
        uint32_t sw = load_le32(seeds + ((r & 3) * 4));
        uint32_t salt = 0x7E3A19C5u ^ (uint32_t)r * 0x45D9F3Bu ^
                        (uint32_t)a_share * 0x01010101u ^
                        rol32(lane_ctx, (unsigned)(r + 3));
        uint32_t lane = material_compress_lane32(a ^ sw, b, c ^ d, salt, (unsigned)r);
        uint32_t ch = mba_ch32(a ^ sw, b, c, salt ^ 0xD6E8FEB8u);
        uint32_t maj = mba_maj32(a, c ^ sw, d, salt ^ 0xC2B2AE35u);
        uint32_t poly = mba_poly32(b ^ sw, c + salt + lane, d ^ (uint32_t)a_share,
                                   salt ^ 0x165667B1u);
        uint32_t f = mba_fbox32(mba_xor32(b ^ ch ^ lane,
                                          rol32(c ^ maj, (unsigned)(r + 3)),
                                          salt),
                                mba_xor32(sw ^ poly, d ^ rol32(lane, r + 1),
                                          salt ^ 0xA0761D64u));
        uint32_t g = mba_mds32(mba_xor32(a ^ maj, f ^ poly ^ lane,
                                         salt ^ 0xE7037ED1u));
        uint32_t feed = (uint32_t)(((a ^ lane) & rol32(b, (unsigned)(r + 5))) ^
                                   ((~b) & rol32(c ^ d ^ ch ^ lane, (unsigned)(r + 1))));
        a = rol32(mba_add32(a ^ lane, mba_xor32(g, feed, salt ^ 0x8EBC6AF1u),
                            salt ^ 0xD6E8FEB8u),
                  (unsigned)(5 + ((r ^ lane) & 7)));
        b = mba_xor32(rol32(mba_add32(b, (a * (0x9E3779B1u + (uint32_t)r * 2u)) ^ lane,
                                       salt ^ 0xC2B2AE35u),
                            (unsigned)(11 + ((r + (lane >> 3)) & 15))),
                      mba_inv_mds32(g) ^ ch ^ material_compress_lane32(lane, c, d, salt ^ g, (unsigned)(r + 3)),
                      salt ^ 0x165667B1u);
        c = mba_add32(c ^ rol32(a ^ poly ^ lane, (unsigned)(r + 7)),
                      b ^ sw ^ maj,
                      salt ^ 0x85EBCA77u);
        d = rol32(d + mba_xor32(c ^ ch, (a ^ lane) >> ((r & 7) + 1), salt ^ 0x27D4EB2Fu),
                  (unsigned)(3 + ((r * 5 + (lane & 7u)) & 15)));
        lane_ctx = mba_add32(lane_ctx ^ lane,
                             material_compress_lane32(a, b ^ c, d, salt ^ lane, (unsigned)(r + 7)),
                             salt ^ 0x589965CCu);
    }

    uint32_t x = mba_xor32_inline_v1(a, rol32(b, 13), 0x6A09E667u);
    x = mba_add32_inline_v1(x, mba_xor32_inline_v1(c, rol32(d, 19), 0xBB67AE85u), 0x3C6EF372u);
    x = mba_xor32_inline_v1(x, ((uint32_t)a_share * 0x01020408u) ^ lane_ctx, 0xA54FF53Au);
    return mba_inv_feistel32(mba_feistel32(x, x ^ load_le32(soKey + 8)), x ^ load_le32(soKey + 8));
}

/* ── 方案 B 内部验证 ─────────────────────────────────────── */
static int verify_scheme_b(const uint8_t *flagB, const uint8_t *soKey, uint8_t a_share) {
    struct runtime_params params;
    key_schedule(flagB, soKey, &params);

    /* Oracle 比对：shellcode 返回 seeds[16] + encoded material[0:8] + tag[8].
     * 不暴露完整 material[0:16]，也不直接暴露 material 头部明文。 */
    extern volatile uint8_t g_sokey_for_oracle[16];
    for (int i = 0; i < 16; i++)
        g_sokey_for_oracle[i] = soKey[i];

    uint8_t oracle_data[32] = {0};
    int oracle_status = get_oracle_material(oracle_data);

    /* oracle_data[0:16] = seeds, oracle_data[16:24] = encoded material[0:8],
     * oracle_data[24:32] = tag(seeds, soKey, schemeA share). */
    /* 验证 seeds */
    volatile uint8_t seeds_diff = 0;
    uint8_t *expected_seeds = (uint8_t *)params.sbox_seeds;
    for (int i = 0; i < 16; i++)
        seeds_diff |= mba_xor8(expected_seeds[i], oracle_data[i], 0xD6E8FEB8u ^ (uint32_t)i);

    /* 验证 material[0:8] 的编码投影。后 8 字节不暴露，保留约束求解门槛。 */
    uint8_t material_head[16];
    uint8_t material_encoded[8];
    expand_key_material(flagB, material_head, 16);
    encode_oracle_material_head(material_head, oracle_data, soKey, a_share, material_encoded);
    uint32_t lane_ctx = derive_lane_context(material_head, material_encoded,
                                            oracle_data, soKey, a_share);
    volatile uint8_t mat_diff = 0;
    for (int i = 0; i < 8; i++)
        mat_diff |= mba_xor8(material_encoded[i], oracle_data[16 + i], 0xA0761D64u ^ (uint32_t)i);

    uint8_t cx_key[16];
    get_const_xor_key(cx_key);
    uint32_t bait_z_b = kctf_bait_zero_mask(0x6B02u,
        load_le32(material_head) ^ load_le32(soKey) ^ ((uint32_t)a_share << 24) ^ lane_ctx);
    uint32_t expected_mid_tag = load_material_expected_enc(0u) ^ load_le32(cx_key) ^ bait_z_b;
    uint32_t mid_tag = derive_material_mid_tag(material_head, oracle_data, soKey, a_share, lane_ctx);
    uint32_t mid_tag_word_diff = mba_xor32(mid_tag, expected_mid_tag, 0x165667B1u);
    uint8_t mid_tag_diff = (uint8_t)(mid_tag_word_diff | (mid_tag_word_diff >> 8) |
                                     (mid_tag_word_diff >> 16) | (mid_tag_word_diff >> 24));

    uint32_t expected_lane_hint_lo = load_material_expected_enc(1u) ^ load_le32(cx_key + 4) ^ bait_z_b;
    uint32_t expected_lane_hint_hi = load_material_expected_enc(2u) ^ load_le32(cx_key + 8) ^ rol32(bait_z_b, 7);
    uint64_t expected_lane_hint = ((uint64_t)expected_lane_hint_lo |
                                   ((uint64_t)expected_lane_hint_hi << 32)) & MATERIAL_LANE_HINT_MASK;
    uint64_t lane_hint = derive_material_lane_hint(material_head, oracle_data, soKey, a_share, lane_ctx);
    uint64_t lane_hint_word_diff = (lane_hint ^ expected_lane_hint) & MATERIAL_LANE_HINT_MASK;
    uint32_t lane_hint_diff_lo = (uint32_t)lane_hint_word_diff;
    uint32_t lane_hint_diff_hi = (uint32_t)(lane_hint_word_diff >> 32);
    uint8_t lane_hint_diff = (uint8_t)(lane_hint_diff_lo | (lane_hint_diff_lo >> 8) |
                                       (lane_hint_diff_lo >> 16) | (lane_hint_diff_lo >> 24) |
                                       lane_hint_diff_hi | (lane_hint_diff_hi >> 8) |
                                       (lane_hint_diff_hi >> 16) | (lane_hint_diff_hi >> 24));

    volatile uint8_t tag_diff = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t tag = mba_xor8(oracle_data[i], oracle_data[8 + i], 0x8EBC6AF1u ^ (uint32_t)i);
        tag = mba_xor8(tag, soKey[(i + 5) & 0x0F], 0x589965CCu ^ (uint32_t)i);
        tag = mba_xor8(tag,
                       mba_trunc8_u32(0xC3u + (uint32_t)i * 0x29u, 0xB492B66Fu ^ (uint32_t)i),
                       0x9E3779B9u ^ (uint32_t)i);
        tag = mba_xor8(tag,
                       mba_trunc8_u32((uint32_t)a_share + (uint32_t)i * 0x17u, 0xC2B2AE35u ^ (uint32_t)i),
                       0x165667B1u ^ (uint32_t)i);
        tag = mba_xor8(tag,
                       mba_trunc8_u32(lane_ctx >> ((i & 3) * 8), 0x510E527Fu ^ (uint32_t)i),
                       0x5BE0CD19u ^ (uint32_t)i);
        tag_diff |= mba_xor8(tag, oracle_data[24 + i], 0x27D4EB2Fu ^ (uint32_t)i);
    }

    uint8_t sboxes[SPN_SBOXES][256];
    for (int i = 0; i < SPN_SBOXES; i++)
        generate_sbox(params.sbox_seeds[i], sboxes[i]);

    /* 第一次 SPN（IV1）*/
    uint8_t state[STATE_LEN];
    memcpy(state, IV, STATE_LEN);
    spn_encrypt(state, &params, sboxes);

    uint8_t expected[STATE_LEN];
    const_xor_load_split(expected, ENC_EXPECTED_STATE_S0, ENC_EXPECTED_STATE_S1, 0xB3u);
    for (int i = 0; i < STATE_LEN; i++)
        expected[i] ^= soKey[i];
    apply_cross_mask(expected, a_share, 0xB1u);

    volatile uint8_t diff = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff |= mba_xor8(state[i], expected[i], 0x85EBCA77u ^ (uint32_t)i);

    /* 第二次 SPN（IV2）：总约束 256 bit > 200 bit，保证唯一性 */
    uint8_t state2[STATE_LEN];
    memcpy(state2, IV2, STATE_LEN);
    spn_encrypt(state2, &params, sboxes);

    uint8_t expected2[STATE_LEN];
    const_xor_load_split(expected2, ENC_EXPECTED_STATE2_S0, ENC_EXPECTED_STATE2_S1, 0xC5u);
    for (int i = 0; i < STATE_LEN; i++)
        expected2[i] ^= soKey[i];
    apply_cross_mask(expected2, a_share, 0xB2u);

    volatile uint8_t diff2 = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff2 |= mba_xor8(state2[i], expected2[i], 0xC3A5C85Cu ^ (uint32_t)i);

    uint8_t oracle_diff = (uint8_t)mba_nonzero_mask32((uint32_t)oracle_status, 0xB492B66Fu);
    uint8_t preclean = (uint8_t)(diff | diff2 | seeds_diff | mat_diff | mid_tag_diff |
                                 lane_hint_diff | tag_diff | oracle_diff);

    uint8_t fake_diff = fake_material_decoy(flagB, a_share, lane_ctx);
    uint8_t fake_expected = load_material_fake_syndrome_enc() ^ cx_key[0];
    uint8_t fake_seed = mba_xor8(preclean, (uint8_t)((uint32_t)oracle_status * 0x5Du), 0xC3A5C85Cu);
    fake_seed = mba_xor8(fake_seed, mba_xor8(seeds_diff, tag_diff, 0xB492B66Fu), 0x9E3779B9u);
    uint8_t fake_mask = (uint8_t)~mba_nonzero_mask8(fake_seed, 0x7F4A7C15u);
    fake_diff = mba_xor8(fake_diff, fake_expected, 0xD1B54A32u) & fake_mask;

    uint8_t ok = (uint8_t)(preclean | fake_diff);

    secure_bzero(&params, sizeof(params));
    secure_bzero(oracle_data, sizeof(oracle_data));
    secure_bzero(material_head, sizeof(material_head));
    secure_bzero(material_encoded, sizeof(material_encoded));
    secure_bzero(cx_key, sizeof(cx_key));
    secure_bzero(sboxes, sizeof(sboxes));
    secure_bzero(state, sizeof(state));
    secure_bzero(expected, sizeof(expected));
    secure_bzero(state2, sizeof(state2));
    secure_bzero(expected2, sizeof(expected2));

    return (ok == 0) ? 1 : 0;
}

/*
 * nativeProcessInput — 主入口
 *
 * 输入：50 字节交错 flag
 *   input[i*2]   → flagA[i]  (i=0..24)  方案 A
 *   input[i*2+1] → flagB[i]  (i=0..24)  方案 B
 *
 * 顺序依赖：方案 A 通过后才运行方案 B。
 * 方案 A 失败 → 返回 0（不泄露是哪个方案失败）。
 */
JNIEXPORT jint JNICALL
Java_com_autorun_kctf_MainActivity_nativeProcessInput(
        JNIEnv *env, jobject obj, jbyteArray jflag) {

    /* 1. 提取 50 字节 */
    uint8_t input[FLAG_LEN];
    (*env)->GetByteArrayRegion(env, jflag, 0, FLAG_LEN, (jbyte *)input);

    /* 2. 交错拆分 */
    uint8_t flagA[FLAG_HALF], flagB[FLAG_HALF];
    for (int i = 0; i < FLAG_HALF; i++) {
        flagA[i] = input[i * 2];
        flagB[i] = input[i * 2 + 1];
    }

    /* 不透明谓词：用 input[0] 驱动花指令条件。
     * IDA 不知道输入值 → 无法确定花指令分支方向。
     * 选手不能 patch 此值 → input[0] 参与方案 A 的 repair_cfg 验证。 */
    g_opaque = input[0];

    /* 3. 获取 soKey */
    uint8_t soKey[SOKEY_LEN];
    fetch_sokey(env, obj, soKey);

    uint8_t material_for_a[96];
    expand_key_material(flagB, material_for_a, sizeof(material_for_a));
    uint8_t material_share = derive_material_share(material_for_a);

    /* 4. 两个方案都执行，避免 coverage trace 直接观察阶段进度 */
    uint8_t a_share = 0;
    int okA = verify_scheme_a(flagA, soKey, material_share, &a_share);
    int okB = verify_scheme_b(flagB, soKey, a_share);
    int result = (okA & okB) ? 1 : 0;

    secure_bzero(input, sizeof(input));
    secure_bzero(flagA, sizeof(flagA));
    secure_bzero(flagB, sizeof(flagB));
    secure_bzero(material_for_a, sizeof(material_for_a));
    secure_bzero(soKey, sizeof(soKey));
    return result;
}
