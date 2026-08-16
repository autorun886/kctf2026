/*
 * seeds_oracle.c — mmap 加载并执行 shellcode，返回 oracle_data[32]
 *
 * 流程：
 *   1. get_oracle_key() 4-share 派生 XOR 解密密钥
 *   2. mmap RWX 页
 *   3. XOR 解密 shellcode 到 mmap 区域
 *   4. 调用 shellcode（内部做反 frida/调试/模拟/hook 检测）
 *   5. 检测通过 → 返回 seeds[16] + material[0:8] + tag[8]
 *      检测失败 → exit_group(1)
 *   6. memset 清零 + munmap
 *
 * Key 保护设计（4-share）：
 *   final_key = share_0 ⊕ share_1 ⊕ share_2 ⊕ oracle_env_share
 *
 *   share_0: MBA 混淆的常量派生（常量内嵌为 immediate，不在 .rodata）
 *   share_1: expand_key_material 函数代码的 CRC32 变换（self-referential）
 *   share_2: soKey 前 8 字节的变换（绑定到 APK 完整性）
 *   oracle_env_share: C 层 preflight 反调试/反 hook 的 clean-path share
 *
 * 蜜罐设计：
 *   g_cached_key（假值）+ g_key_debug_override 诱导 AI 走错误路径
 */
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include "include/kctf.h"

/* 引用 .S 中定义的 shellcode 字节区间 */
extern const uint8_t oracle_code_start[];
extern const uint8_t oracle_code_end[];

/* ═══════════════════════════════════════════════════════
 * 蜜罐（不变）
 * ═══════════════════════════════════════════════════════ */
static volatile int    g_key_cache_valid = 1;
static volatile uint8_t g_cached_key[16] = {
    0xA3, 0x7B, 0x4F, 0x1D, 0xE8, 0x56, 0x92, 0xC4,
    0x3D, 0x0E, 0xF1, 0x68, 0xB5, 0x27, 0xDA, 0x8C
};
volatile int g_key_debug_override = 0;

/* soKey 缓存——由 jni_entry.c 的 verify_scheme_b 写入 */
volatile uint8_t g_sokey_for_oracle[16] = {0};


static uint8_t oracle_gf_mul(uint8_t a, uint8_t b) {
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

static uint32_t oracle_mds32(uint32_t x) {
    uint8_t a0 = (uint8_t)x, a1 = (uint8_t)(x >> 8);
    uint8_t a2 = (uint8_t)(x >> 16), a3 = (uint8_t)(x >> 24);
    uint8_t b0 = oracle_gf_mul(a0, 2) ^ oracle_gf_mul(a1, 3) ^ a2 ^ a3;
    uint8_t b1 = a0 ^ oracle_gf_mul(a1, 2) ^ oracle_gf_mul(a2, 3) ^ a3;
    uint8_t b2 = a0 ^ a1 ^ oracle_gf_mul(a2, 2) ^ oracle_gf_mul(a3, 3);
    uint8_t b3 = oracle_gf_mul(a0, 3) ^ a1 ^ a2 ^ oracle_gf_mul(a3, 2);
    return (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
}

static uint32_t oracle_inv_mds32(uint32_t x) {
    uint8_t a0 = (uint8_t)x, a1 = (uint8_t)(x >> 8);
    uint8_t a2 = (uint8_t)(x >> 16), a3 = (uint8_t)(x >> 24);
    uint8_t b0 = oracle_gf_mul(a0, 0x0e) ^ oracle_gf_mul(a1, 0x0b) ^ oracle_gf_mul(a2, 0x0d) ^ oracle_gf_mul(a3, 0x09);
    uint8_t b1 = oracle_gf_mul(a0, 0x09) ^ oracle_gf_mul(a1, 0x0e) ^ oracle_gf_mul(a2, 0x0b) ^ oracle_gf_mul(a3, 0x0d);
    uint8_t b2 = oracle_gf_mul(a0, 0x0d) ^ oracle_gf_mul(a1, 0x09) ^ oracle_gf_mul(a2, 0x0e) ^ oracle_gf_mul(a3, 0x0b);
    uint8_t b3 = oracle_gf_mul(a0, 0x0b) ^ oracle_gf_mul(a1, 0x0d) ^ oracle_gf_mul(a2, 0x09) ^ oracle_gf_mul(a3, 0x0e);
    return (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
}

static uint32_t oracle_fbox32(uint32_t x, uint32_t k) {
    x ^= k;
    x *= 0x45D9F3Bu;
    x ^= x >> 16;
    x *= 0x119DE1F3u;
    x ^= x >> 15;
    return x;
}

static uint32_t oracle_feistel32(uint32_t x, uint32_t k) {
    uint16_t l = (uint16_t)x, r = (uint16_t)(x >> 16);
    l ^= (uint16_t)oracle_fbox32(r, k);
    r ^= (uint16_t)oracle_fbox32(l, k ^ 0x9E37u);
    return (uint32_t)l | ((uint32_t)r << 16);
}

static uint32_t oracle_inv_feistel32(uint32_t x, uint32_t k) {
    uint16_t l = (uint16_t)x, r = (uint16_t)(x >> 16);
    r ^= (uint16_t)oracle_fbox32(l, k ^ 0x9E37u);
    l ^= (uint16_t)oracle_fbox32(r, k);
    return (uint32_t)l | ((uint32_t)r << 16);
}

static uint32_t oracle_identity32(uint32_t x, uint32_t salt) {
    uint32_t k = oracle_fbox32(salt, 0xD1B54A32u);
    uint32_t y = oracle_inv_mds32(oracle_mds32(x ^ k)) ^ k;
    return oracle_inv_feistel32(oracle_feistel32(y, k ^ 0x94D049BBu), k ^ 0x94D049BBu);
}

static uint8_t oracle_loader_mask_byte(size_t i, size_t code_size,
                                       const uint8_t key[16], uint32_t phase) {
    uint32_t x = ((uint32_t)i * 0x45D9F3Bu) ^ (uint32_t)code_size ^ phase;
    x ^= (uint32_t)key[(i + (phase >> 3)) & 0x0F] << ((i & 3u) * 8u);
    x = oracle_identity32(x ^ (x >> 13), phase ^ (uint32_t)i ^ 0x6C8E9CF5u);
    return (uint8_t)(x ^ (x >> 8) ^ (x >> 19));
}

static uint8_t oracle_loader_poison_byte(size_t i, uint32_t bait_zero) {
    uint32_t x = oracle_identity32(bait_zero ^ ((uint32_t)i * 0x9E3779B9u),
                                   0xD00DFEEDu ^ (uint32_t)i);
    uint32_t live = 0u - (uint32_t)(bait_zero != 0u);
    return (uint8_t)(x & live);
}

typedef void *(*oracle_mmap_fn_t)(void *, size_t, int, int, int, long);
typedef int (*oracle_munmap_fn_t)(void *, size_t);

#define ORACLE_AARCH64_NR_MUNMAP 215L
#define ORACLE_AARCH64_NR_MMAP   222L

static long oracle_svc6(long nr, long a0, long a1, long a2,
                        long a3, long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "cc", "memory");
    return x0;
}

static void *oracle_svc_mmap_pages(size_t alloc_size, int prot) {
    long ret = oracle_svc6(ORACLE_AARCH64_NR_MMAP, 0, (long)alloc_size,
                           (long)prot, (long)(MAP_PRIVATE | MAP_ANONYMOUS),
                           -1, 0);
    if (ret < 0 && ret > -4096)
        return MAP_FAILED;
    return (void *)(uintptr_t)ret;
}

static int oracle_svc_munmap_pages(void *mem, size_t alloc_size) {
    long ret = oracle_svc6(ORACLE_AARCH64_NR_MUNMAP,
                           (long)(uintptr_t)mem, (long)alloc_size,
                           0, 0, 0, 0);
    if (ret < 0 && ret > -4096)
        return -1;
    return (int)ret;
}

static void *oracle_map_pages(size_t alloc_size, int prot, uint32_t salt) {
    uintptr_t fp = (uintptr_t)get_func_by_id(8);
    uint32_t zero = kctf_bait_zero_mask(0x4D4Du,
        salt ^ (uint32_t)alloc_size ^ (uint32_t)(fp >> 4));
    oracle_mmap_fn_t p_mmap = (oracle_mmap_fn_t)(fp ^ (uintptr_t)zero);

    if (p_mmap) {
        void *mem = p_mmap(NULL, alloc_size, prot,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem != MAP_FAILED)
            return mem;
    }
    return oracle_svc_mmap_pages(alloc_size, prot);
}

static int oracle_unmap_pages(void *mem, size_t alloc_size, uint32_t salt) {
    uintptr_t fp = (uintptr_t)get_func_by_id(9);
    uint32_t zero = kctf_bait_zero_mask(0x4D55u,
        salt ^ (uint32_t)(uintptr_t)mem ^ (uint32_t)alloc_size ^
        (uint32_t)(fp >> 5));
    oracle_munmap_fn_t p_munmap = (oracle_munmap_fn_t)(fp ^ (uintptr_t)zero);

    if (p_munmap)
        return p_munmap(mem, alloc_size);
    return oracle_svc_munmap_pages(mem, alloc_size);
}

static void oracle_touch_decoy_map(const uint8_t *src, size_t code_size,
                                   size_t alloc_size, const uint8_t key[16],
                                   const uint8_t bait_cache[16],
                                   uint32_t bait_zero) {
    void *decoy = oracle_map_pages(alloc_size, PROT_READ | PROT_WRITE,
        (uint32_t)((uintptr_t)src ^ code_size ^ bait_zero ^ 0xDEC0A11Cu));
    if (decoy == MAP_FAILED)
        return;

    volatile uint8_t *dst = (volatile uint8_t *)decoy;
    uint32_t roll = oracle_identity32((uint32_t)code_size ^ bait_zero ^ 0xE17A5EEDu,
                                      (uint32_t)(uintptr_t)src);
    size_t n = code_size < 128 ? code_size : 128;
    for (size_t i = 0; i < n; i++) {
        roll = oracle_identity32(roll ^ (uint32_t)i ^
                                 ((uint32_t)bait_cache[(i * 5u + 3u) & 0x0F] << 24),
                                 0x6D0F27BDu ^ (uint32_t)i);
        dst[i] = (uint8_t)(src[i] ^ bait_cache[(i + roll) & 0x0F] ^
                           key[(i * 3u + 5u) & 0x0F] ^ (uint8_t)roll);
    }
    for (size_t i = n; i > 0; i--) {
        dst[i - 1] = (uint8_t)(dst[i - 1] ^
                               oracle_loader_mask_byte(i - 1, code_size, key, roll));
    }

    secure_bzero(decoy, alloc_size);
    oracle_unmap_pages(decoy, alloc_size,
        roll ^ (uint32_t)((uintptr_t)src >> 3) ^ 0xDEC0DE01u);
}

/* ═══════════════════════════════════════════════════════
 * Oracle preflight share
 *
 * 明显的 C 层反调试不直接 gate oracle，而是影响 shellcode XOR key。
 * clean path 输出固定 share；任何异常输出确定但错误的 bad share。
 * converge.py 使用同一个 clean share 来加密发布版 shellcode。
 * ═══════════════════════════════════════════════════════ */
static uint8_t oracle_env_clean_byte(int i) {
    uint32_t x = 0xC3D2E1F0u ^ ((uint32_t)i * 0x45D9F3Bu);
    x = oracle_identity32(x ^ (x >> 16), (uint32_t)i ^ 0xC2B2AE35u);
    x *= 0x7FEB352Du;
    x = oracle_identity32(x ^ (x >> 15), (uint32_t)i ^ 0x27D4EB2Fu);
    uint32_t y = oracle_identity32(x ^ (x >> 8) ^ (0xA7u + (uint32_t)i * 0x31u), (uint32_t)i ^ 0x165667B1u);
    return (uint8_t)y;
}

static uint32_t oracle_hook_signature(void *fn) {
    if (!fn) return 0;
    const volatile uint32_t *code = (const volatile uint32_t *)fn;
    uint32_t prev_ldr = 0;
    uint32_t sig = 0;
    for (int i = 0; i < 6; i++) {
        uint32_t insn = code[i];
        if ((insn & 0x7C000000u) == 0x14000000u)
            sig ^= 0x01010101u << (i & 3);  /* B/BL immediate */
        if ((insn & 0xFFE00000u) == 0xD4200000u)
            sig ^= 0x3D5A7C11u ^ (uint32_t)i;  /* BRK breakpoint */
        if (prev_ldr) {
            uint32_t op = insn & 0xFFFFFC1Fu;
            if (op == 0xD61F0000u || op == 0xD63F0000u)
                sig ^= 0x6B2D41E9u + (uint32_t)i;  /* BR/BLR after literal load */
        }
        prev_ldr = ((insn & 0xFF000000u) == 0x58000000u);
    }
    return sig;
}

static int oracle_tracer_bad(void) {
    typedef int (*fn_open)(const char *, int);
    typedef long (*fn_read)(int, void *, unsigned long);
    typedef int (*fn_close)(int);
    fn_open p_open = (fn_open)get_func_by_id(4);
    fn_read p_read = (fn_read)get_func_by_id(5);
    fn_close p_close = (fn_close)get_func_by_id(6);
    if (!p_open || !p_read || !p_close) return 0;

    int fd = p_open(get_string(0), 0);
    if (fd < 0) return 0;
    char buf[512];
    long n = p_read(fd, buf, sizeof(buf) - 1);
    p_close(fd);
    if (n <= 0) return 0;
    buf[(n < (long)sizeof(buf)) ? n : ((long)sizeof(buf) - 1)] = 0;

    for (long i = 0; i + 10 < n; i++) {
        if (buf[i] == 'T' && buf[i + 1] == 'r' && buf[i + 5] == 'r' && buf[i + 6] == 'P') {
            i += 10;
            while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
            uint32_t pid = 0;
            while (i < n && buf[i] >= '0' && buf[i] <= '9') {
                pid = pid * 10u + (uint32_t)(buf[i] - '0');
                i++;
            }
            return pid != 0;
        }
    }
    return 0;
}

static int oracle_maps_bad(void) {
    typedef int (*fn_open)(const char *, int);
    typedef long (*fn_read)(int, void *, unsigned long);
    typedef int (*fn_close)(int);
    fn_open p_open = (fn_open)get_func_by_id(4);
    fn_read p_read = (fn_read)get_func_by_id(5);
    fn_close p_close = (fn_close)get_func_by_id(6);
    if (!p_open || !p_read || !p_close) return 0;

    int fd = p_open(get_string(2), 0);
    if (fd < 0) return 0;
    char buf[512];
    int bad = 0;
    for (;;) {
        long n = p_read(fd, buf, sizeof(buf));
        if (n <= 4) break;
        for (long i = 0; i + 4 <= n; i++) {
            uint32_t w = (uint8_t)buf[i] | ((uint32_t)(uint8_t)buf[i + 1] << 8)
                       | ((uint32_t)(uint8_t)buf[i + 2] << 16)
                       | ((uint32_t)(uint8_t)buf[i + 3] << 24);
            if (w == 0x64697266u || w == 0x736F7078u || w == 0x67646167u) {
                bad = 1;
                break;
            }
        }
        if (bad) break;
    }
    p_close(fd);
    return bad;
}

static void compute_oracle_env_share(uint8_t out[16]) {
    KCTF_HONEY_BR_BAIT_TBZ(0xC805u,
        (uint32_t)((uintptr_t)oracle_code_start ^ (uintptr_t)oracle_code_end) ^
        ((uint32_t)g_sokey_for_oracle[0] << 16));
    KCTF_REAL_BR_FALSE_BAIT_CSEL(0xF805u,
        ((uint32_t)g_sokey_for_oracle[1] | ((uint32_t)g_sokey_for_oracle[9] << 8)) ^
        (uint32_t)((uintptr_t)oracle_code_start >> 4),
        get_oracle_material);

    uint32_t flags = 0;
    uint32_t bad_mix = 0;
    uint32_t bad = (uint32_t)oracle_tracer_bad();
    flags |= bad << 0;
    bad_mix ^= (0u - bad) & oracle_identity32(0x13579BDFu, 0xA5A55A5Au);
    bad = (uint32_t)oracle_maps_bad();
    flags |= bad << 1;
    bad_mix ^= (0u - bad) & oracle_identity32(0x2468ACE0u, 0x5A5AA5A5u);

    unsigned long hwcap = getauxval(16);  /* AT_HWCAP */
    bad = (uint32_t)(((hwcap & 0x3UL) != 0x3UL) ? 1u : 0u);
    flags |= bad << 2;
    bad_mix ^= (0u - bad) & oracle_identity32(0x31415926u, 0x27182818u);

    static const uint8_t ids[5] = {0, 4, 5, 7, 8};
    static const uint32_t poison[5] = {
        0xC10C6E7Du, 0x0F3A0D55u, 0x51EAD5A7u, 0xA7C0F11Du, 0x4D4D4150u
    };
    for (int i = 0; i < 5; i++) {
        uint32_t sig = oracle_hook_signature(get_func_by_id(ids[i]));
        uint32_t hit = (uint32_t)(sig != 0u);
        flags |= hit << (3 + i);
        bad_mix ^= (0u - hit) & oracle_identity32(poison[i] ^ sig,
                                                  poison[(i + 2) % 5] ^ (uint32_t)i);
    }

    bad_mix = oracle_identity32(bad_mix ^ (flags * 0x9E3779B9u), flags ^ 0x85EBCA77u);
    for (int i = 0; i < 16; i++) {
        uint8_t clean = oracle_env_clean_byte(i);
        uint32_t x = bad_mix + ((uint32_t)i * 0x85EBCA6Bu);
        x = oracle_identity32(x ^ (x >> ((i & 7) + 5)), bad_mix ^ (uint32_t)i);
        out[i] = (uint8_t)(clean ^ (uint8_t)x);
    }
}

/* ═══════════════════════════════════════════════════════
 * Share 0: MBA 混淆常量派生
 *
 * 原始逻辑: Feistel(_kdf_iv) → 8 bytes
 * 混淆后: 常量通过 MOVZ/MOVK 内嵌（编译器将其放入 .text 而非 .rodata）
 *         运算用 MBA 恒等式替换，反编译结果难以化简
 * ═══════════════════════════════════════════════════════ */

/* MBA 恒等式:
 * x + y == (x ^ y) + 2*(x & y)
 * x - y == (x ^ y) - 2*(~x & y)
 * x ^ y == (x | y) - (x & y)
 * 这些在反编译输出中看起来像无意义的位运算组合 */

/* MBA 混淆的加法: 返回 a + b */
static inline __attribute__((always_inline))
uint32_t mba_add(uint32_t a, uint32_t b) {
    /* a + b == (a ^ b) + 2*(a & b) */
    return (a ^ b) + ((a & b) << 1);
}

/* MBA 混淆的 XOR: 返回 a ^ b */
static inline __attribute__((always_inline))
uint32_t mba_xor(uint32_t a, uint32_t b) {
    /* a ^ b == (a | b) - (a & b) */
    return (a | b) - (a & b);
}

/* MBA 混淆的 round function */
static inline __attribute__((always_inline))
uint32_t mba_f(uint32_t x, uint32_t k) {
    x = mba_add(x, k);
    x = mba_xor(x, x >> 16);
    x *= 0x45D9F3B;
    x = mba_xor(x, x >> 16);
    return x;
}

static void compute_share0(uint8_t out[8]) {
    /* 常量原本是 SHA-256 IV（_kdf_iv），现在直接内嵌为局部变量
     * 编译器将它们编码为 MOVZ/MOVK 指令，不会出现在 .rodata 中 */
    volatile uint32_t c0 = 0x6A09E667;
    volatile uint32_t c1 = 0xBB67AE85;
    volatile uint32_t c2 = 0x3C6EF372;
    volatile uint32_t c3 = 0xA54FF53A;
    volatile uint32_t c4 = 0x510E527F;
    volatile uint32_t c5 = 0x9B05688C;
    volatile uint32_t c6 = 0x1F83D9AB;
    volatile uint32_t c7 = 0x5BE0CD19;

    /* 4 轮 MBA-Feistel */
    uint32_t L = mba_xor(c0, c2);
    uint32_t R = mba_xor(c1, c3);
    uint32_t tmp;

    tmp = R; R = mba_xor(L, mba_f(R, c4)); L = tmp;
    tmp = R; R = mba_xor(L, mba_f(R, c5)); L = tmp;
    tmp = R; R = mba_xor(L, mba_f(R, c6)); L = tmp;
    tmp = R; R = mba_xor(L, mba_f(R, c7)); L = tmp;

    /* 输出 8 字节 */
    out[0] = (uint8_t)(L);       out[1] = (uint8_t)(L >> 8);
    out[2] = (uint8_t)(L >> 16); out[3] = (uint8_t)(L >> 24);
    out[4] = (uint8_t)(R);       out[5] = (uint8_t)(R >> 8);
    out[6] = (uint8_t)(R >> 16); out[7] = (uint8_t)(R >> 24);
}

/* ═══════════════════════════════════════════════════════
 * Share 1: Self-Referential 函数哈希
 *
 * 读取 expand_key_material 函数前 64 字节机器码
 * 用半字节 CRC32 变换得到 8 字节
 * 效果: patch expand_key_material → hash 变 → key 错 → 保护完整性
 * ═══════════════════════════════════════════════════════ */
static void compute_share1(uint8_t out[8]) {
    static const uint32_t crc_tab[16] = {
        0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
        0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
        0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
        0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
    };

    /* 读 expand_key_material 前 64 字节代码 */
    const uint8_t *code = (const uint8_t *)(void *)expand_key_material;

    /* CRC32 前 32 字节 → share1[0:4] */
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < 32; i++) {
        crc ^= code[i];
        crc = (crc >> 4) ^ crc_tab[crc & 0x0F];
        crc = (crc >> 4) ^ crc_tab[crc & 0x0F];
    }
    crc ^= 0xFFFFFFFF;
    out[0] = (uint8_t)(crc);       out[1] = (uint8_t)(crc >> 8);
    out[2] = (uint8_t)(crc >> 16); out[3] = (uint8_t)(crc >> 24);

    /* CRC32 后 32 字节 → share1[4:8] */
    crc = 0xFFFFFFFF;
    for (int i = 32; i < 64; i++) {
        crc ^= code[i];
        crc = (crc >> 4) ^ crc_tab[crc & 0x0F];
        crc = (crc >> 4) ^ crc_tab[crc & 0x0F];
    }
    crc ^= 0xFFFFFFFF;
    out[4] = (uint8_t)(crc);       out[5] = (uint8_t)(crc >> 8);
    out[6] = (uint8_t)(crc >> 16); out[7] = (uint8_t)(crc >> 24);
}

/* ═══════════════════════════════════════════════════════
 * Share 2: soKey 绑定（APK 完整性）
 *
 * soKey 来自 Java CRC32(.text)→LCG，已由 jni_entry 写入 g_sokey_for_oracle
 * 对 soKey 前 8 字节做简单非线性变换
 * ═══════════════════════════════════════════════════════ */
static void compute_share2(uint8_t out[8]) {
    const volatile uint8_t *sk = g_sokey_for_oracle;

    /* 非线性混合: 每字节与相邻字节做旋转异或 */
    for (int i = 0; i < 8; i++) {
        uint8_t a = sk[i];
        uint8_t b = sk[(i + 3) & 0x0F];  /* soKey[i+3 mod 16] */
        uint8_t c = sk[(i + 7) & 0x0F];  /* soKey[i+7 mod 16] */
        out[i] = a ^ ((b << 3) | (b >> 5)) ^ ((c << 5) | (c >> 3));
    }
}

/* ═══════════════════════════════════════════════════════
 * get_oracle_key — 4-share 组合派生 16 字节 XOR key
 *
 * final_key[0:8]  = share_0 ⊕ share_1 ⊕ share_2 ⊕ env[0:8]
 * final_key[8:16] = share_0_b ⊕ share_1_b ⊕ share_2_b ⊕ env[8:16]
 *   (第二个 8 字节用不同参数再跑一次)
 * ═══════════════════════════════════════════════════════ */
static void get_oracle_key(uint8_t out[16]) {
    /* 蜜罐路径 A */
    if (__builtin_expect(g_key_debug_override, 0)) {
        for (int i = 0; i < 16; i++)
            out[i] = g_cached_key[i];
        return;
    }
    /*
     * Do not early-return from g_cached_key.  The real oracle key depends on
     * g_sokey_for_oracle, which is refreshed by verify_scheme_b() for every
     * nativeProcessInput() call.  Reusing a previous key makes one bad or
     * instrumented verification poison all later attempts in the same process.
     * Keep the cache writes below as decoy state, but always recompute here.
     */

    /* ── 真实 4-share 派生 ── */
    uint8_t s0[8], s1[8], s2[8], env_share[16];
    compute_oracle_env_share(env_share);

    /* 前 8 字节 */
    compute_share0(s0);
    compute_share1(s1);
    compute_share2(s2);
    for (int i = 0; i < 8; i++)
        out[i] = s0[i] ^ s1[i] ^ s2[i] ^ env_share[i];

    /* 后 8 字节：用 share0 的第二组 + share1/share2 翻转 */
    {
        /* share0 第二组: 用另一半常量 */
        volatile uint32_t c4 = 0x510E527F;
        volatile uint32_t c5 = 0x9B05688C;
        volatile uint32_t c6 = 0x1F83D9AB;
        volatile uint32_t c7 = 0x5BE0CD19;
        volatile uint32_t c0 = 0x6A09E667;
        volatile uint32_t c1 = 0xBB67AE85;
        volatile uint32_t c2 = 0x3C6EF372;
        volatile uint32_t c3 = 0xA54FF53A;

        uint32_t L = mba_xor(c4, c6);
        uint32_t R = mba_xor(c5, c7);
        uint32_t tmp;
        tmp = R; R = mba_xor(L, mba_f(R, c0)); L = tmp;
        tmp = R; R = mba_xor(L, mba_f(R, c1)); L = tmp;
        tmp = R; R = mba_xor(L, mba_f(R, c2)); L = tmp;
        tmp = R; R = mba_xor(L, mba_f(R, c3)); L = tmp;

        s0[0] = (uint8_t)(L);       s0[1] = (uint8_t)(L >> 8);
        s0[2] = (uint8_t)(L >> 16); s0[3] = (uint8_t)(L >> 24);
        s0[4] = (uint8_t)(R);       s0[5] = (uint8_t)(R >> 8);
        s0[6] = (uint8_t)(R >> 16); s0[7] = (uint8_t)(R >> 24);
    }

    /* share1 后半: code[64:128] 的 CRC */
    {
        static const uint32_t crc_tab[16] = {
            0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
            0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
            0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
            0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
        };
        const uint8_t *code = (const uint8_t *)(void *)expand_key_material;
        uint32_t crc = 0xFFFFFFFF;
        for (int i = 64; i < 96; i++) {
            crc ^= code[i];
            crc = (crc >> 4) ^ crc_tab[crc & 0x0F];
            crc = (crc >> 4) ^ crc_tab[crc & 0x0F];
        }
        crc ^= 0xFFFFFFFF;
        s1[0] = (uint8_t)(crc);       s1[1] = (uint8_t)(crc >> 8);
        s1[2] = (uint8_t)(crc >> 16); s1[3] = (uint8_t)(crc >> 24);

        crc = 0xFFFFFFFF;
        for (int i = 96; i < 128; i++) {
            crc ^= code[i];
            crc = (crc >> 4) ^ crc_tab[crc & 0x0F];
            crc = (crc >> 4) ^ crc_tab[crc & 0x0F];
        }
        crc ^= 0xFFFFFFFF;
        s1[4] = (uint8_t)(crc);       s1[5] = (uint8_t)(crc >> 8);
        s1[6] = (uint8_t)(crc >> 16); s1[7] = (uint8_t)(crc >> 24);
    }

    /* share2 后半: soKey[8:16] 变换 */
    {
        const volatile uint8_t *sk = g_sokey_for_oracle;
        for (int i = 0; i < 8; i++) {
            uint8_t a = sk[8 + i];
            uint8_t b = sk[(i + 5) & 0x0F];
            uint8_t c = sk[(i + 11) & 0x0F];
            s2[i] = a ^ ((b << 2) | (b >> 6)) ^ ((c << 6) | (c >> 2));
        }
    }

    for (int i = 0; i < 8; i++)
        out[8 + i] = s0[i] ^ s1[i] ^ s2[i] ^ env_share[8 + i];

    secure_bzero(env_share, sizeof(env_share));

    /* 写入 cache（蜜罐）*/
    for (int i = 0; i < 16; i++)
        ((volatile uint8_t *)g_cached_key)[i] = out[i];
    g_key_cache_valid = 2;
}

/* ═══════════════════════════════════════════════════════
 * get_oracle_material — 入口函数
 * ═══════════════════════════════════════════════════════ */
struct oracle_ctx {
    void *mmap_addr;
    void *mprotect_addr;
    void *open_addr;
    void *read_addr;
    void *close_addr;
};

typedef int (*oracle_fn_t)(uint8_t *, const struct oracle_ctx *);

int get_oracle_material(uint8_t out[32]) {
    KCTF_HONEY_BR_BAIT(0xC906u,
        (uint32_t)((uintptr_t)out ^ (uintptr_t)oracle_code_start ^
                   (uintptr_t)(oracle_code_end - oracle_code_start)));
    KCTF_REAL_BR_FALSE_BAIT_TBZ(0xF906u,
        (uint32_t)((uintptr_t)out ^ (uintptr_t)oracle_code_end ^
                   ((uintptr_t)g_sokey_for_oracle[15] << 20)),
        key_schedule);

    size_t code_size = (size_t)(oracle_code_end - oracle_code_start);

    size_t page_size = 4096;
    size_t alloc_size = (code_size + page_size - 1) & ~(page_size - 1);

    void *mem = oracle_map_pages(alloc_size, PROT_READ | PROT_WRITE,
        (uint32_t)((uintptr_t)out ^ (uintptr_t)oracle_code_start ^
                   (uintptr_t)oracle_code_end));
    if (mem == MAP_FAILED)
        return -1;

    uint8_t bait_cache[16];
    for (int i = 0; i < 16; i++)
        bait_cache[i] = ((volatile uint8_t *)g_cached_key)[(i * 7 + 3) & 0x0F];

    /* 4-share 派生 XOR 密钥 */
    uint8_t key[16];
    get_oracle_key(key);

    const uint8_t *src = oracle_code_start;
    uint8_t *dst = (uint8_t *)mem;

    uint32_t bait_zero = kctf_bait_zero_mask(0x6C07u,
        (uint32_t)((uintptr_t)mem ^ (uintptr_t)src ^ code_size ^
                   ((uintptr_t)out >> 3)));
    oracle_touch_decoy_map(src, code_size, alloc_size, key, bait_cache, bait_zero);

    volatile uint8_t *vdst = (volatile uint8_t *)dst;
    for (size_t i = 0; i < code_size; i++) {
        uint8_t mask = oracle_loader_mask_byte(i, code_size, key, 0xA91D3B05u);
        vdst[i] = (uint8_t)(src[i] ^ key[i & 0x0F] ^ mask);
    }
    for (size_t i = 0; i < code_size; i++) {
        uint8_t mask = oracle_loader_mask_byte(i, code_size, key, 0xA91D3B05u);
        uint8_t poison = oracle_loader_poison_byte(i, bait_zero);
        vdst[i] = (uint8_t)(vdst[i] ^ mask ^ poison);
    }

    /* 清除指令缓存 */
    __builtin___clear_cache(mem, (char *)mem + code_size);

    typedef int (*fn_mprotect)(void *, size_t, int);
    fn_mprotect p_mprotect = (fn_mprotect)get_func_by_id(7);
    if (!p_mprotect || p_mprotect(mem, alloc_size, PROT_READ | PROT_EXEC) != 0) {
        secure_bzero(key, sizeof(key));
        secure_bzero(bait_cache, sizeof(bait_cache));
        secure_bzero(mem, alloc_size);
        oracle_unmap_pages(mem, alloc_size,
            (uint32_t)((uintptr_t)mem ^ alloc_size ^ 0xFA17C0DEu));
        return -1;
    }

    struct oracle_ctx ctx;
    ctx.mmap_addr = get_func_by_id(8);
    if (!ctx.mmap_addr)
        ctx.mmap_addr = (void *)(uintptr_t)&oracle_svc_mmap_pages;
    ctx.mprotect_addr = (void *)(uintptr_t)p_mprotect;
    ctx.open_addr = get_func_by_id(4);
    ctx.read_addr = get_func_by_id(5);
    ctx.close_addr = get_func_by_id(6);

    /* 执行 shellcode */
    oracle_fn_t fn = (oracle_fn_t)mem;
    int ret = fn(out, &ctx);

    /* 清零 + 释放 */
    int can_wipe = (p_mprotect(mem, alloc_size, PROT_READ | PROT_WRITE) == 0);
    secure_bzero(key, sizeof(key));
    secure_bzero(bait_cache, sizeof(bait_cache));
    secure_bzero(&ctx, sizeof(ctx));
    if (can_wipe) secure_bzero(mem, alloc_size);
    oracle_unmap_pages(mem, alloc_size,
        (uint32_t)((uintptr_t)fn ^ (uintptr_t)out ^ 0xC1EA12EFu));

    return ret;
}
