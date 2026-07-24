/*
 * seeds_oracle.c — mmap 加载并执行 shellcode，返回 material[0:32]
 *
 * 流程：
 *   1. get_oracle_key() 3-share 派生 XOR 解密密钥
 *   2. mmap RWX 页
 *   3. XOR 解密 shellcode 到 mmap 区域
 *   4. 调用 shellcode（内部做反 frida/调试/模拟检测，全部 SVC）
 *   5. 检测通过 → 返回 material[0:32]；检测失败 → exit_group(1)
 *   6. memset 清零 + munmap
 *
 * Key 保护设计（3-share）：
 *   final_key = share_0 ⊕ share_1 ⊕ share_2
 *
 *   share_0: MBA 混淆的常量派生（常量内嵌为 immediate，不在 .rodata）
 *   share_1: expand_key_material 函数代码的 CRC32 变换（self-referential）
 *   share_2: soKey 前 8 字节的变换（绑定到 APK 完整性）
 *
 * 蜜罐设计：
 *   g_cached_key（假值）+ g_key_debug_override 诱导 AI 走错误路径
 */
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
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
 * get_oracle_key — 3-share 组合派生 16 字节 XOR key
 *
 * final_key[0:8]  = share_0 ⊕ share_1 ⊕ share_2
 * final_key[8:16] = share_0_b ⊕ share_1_b ⊕ share_2_b
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

    /* ── 真实 3-share 派生 ── */
    uint8_t s0[8], s1[8], s2[8];

    /* 前 8 字节 */
    compute_share0(s0);
    compute_share1(s1);
    compute_share2(s2);
    for (int i = 0; i < 8; i++)
        out[i] = s0[i] ^ s1[i] ^ s2[i];

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
        out[8 + i] = s0[i] ^ s1[i] ^ s2[i];

    /* 写入 cache（蜜罐）*/
    for (int i = 0; i < 16; i++)
        ((volatile uint8_t *)g_cached_key)[i] = out[i];
    g_key_cache_valid = 2;
}

/* ═══════════════════════════════════════════════════════
 * get_oracle_material — 入口函数
 * ═══════════════════════════════════════════════════════ */
typedef int (*oracle_fn_t)(uint8_t *);

int get_oracle_material(uint8_t out[32]) {
    size_t code_size = (size_t)(oracle_code_end - oracle_code_start);

    size_t page_size = 4096;
    size_t alloc_size = (code_size + page_size - 1) & ~(page_size - 1);

    void *mem = mmap(NULL, alloc_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
        return -1;

    /* 3-share 派生 XOR 密钥 */
    uint8_t key[16];
    get_oracle_key(key);

    /* XOR 解密 shellcode 到 mmap 区域 */
    const uint8_t *src = oracle_code_start;
    uint8_t *dst = (uint8_t *)mem;
    for (size_t i = 0; i < code_size; i++)
        dst[i] = src[i] ^ key[i & 0x0F];

    /* 清除指令缓存 */
    __builtin___clear_cache(mem, (char *)mem + code_size);

    typedef int (*fn_mprotect)(void *, size_t, int);
    fn_mprotect p_mprotect = (fn_mprotect)get_func_by_id(7);
    if (!p_mprotect || p_mprotect(mem, alloc_size, PROT_READ | PROT_EXEC) != 0) {
        secure_bzero(key, sizeof(key));
        secure_bzero(mem, alloc_size);
        munmap(mem, alloc_size);
        return -1;
    }

    /* 执行 shellcode */
    oracle_fn_t fn = (oracle_fn_t)mem;
    int ret = fn(out);

    /* 清零 + 释放 */
    int can_wipe = (p_mprotect(mem, alloc_size, PROT_READ | PROT_WRITE) == 0);
    secure_bzero(key, sizeof(key));
    if (can_wipe) secure_bzero(mem, alloc_size);
    munmap(mem, alloc_size);

    return ret;
}
