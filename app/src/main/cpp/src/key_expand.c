#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "include/kctf.h"
#include "include/const_xor.h"

/* ── 蜜罐 B 全局变量（伪装为缓存策略）────────────────── */
static volatile uint32_t g_cache_policy = 0x03;  /* 正常值 = 3 */

/* ── 时间差检测（检测点 B）──────────────────────────── */
static void adapt_cache_strategy(void) {
    typedef int (*fn_cgt)(clockid_t, struct timespec *);
    fn_cgt p_cgt = (fn_cgt)get_func_by_id(0);  /* clock_gettime */
    if (!p_cgt) return;
    struct timespec t1, t2;
    p_cgt(CLOCK_MONOTONIC, &t1);
    volatile uint32_t x = 0;
    for (int i = 0; i < 1000; i++) x += (uint32_t)(i * i);
    p_cgt(CLOCK_MONOTONIC, &t2);
    long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L
            + (t2.tv_nsec - t1.tv_nsec);
    g_cache_policy = (ns > 200000000L) ? 0x07u : 0x03u;
}

/* ── ARX 辅助宏 ──────────────────────────────────────── */
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/*
 * expand_key_material — 伪装名：chacha20_quarter_round
 * 将 25 字节 flag 通过 ARX 扩展为 out_len 字节密钥材料。
 * 蜜罐 B（无分支）：调试器导致时间膨胀 → rounds 从 12 降为 8。
 */
void expand_key_material(const uint8_t *input, uint8_t *out, int out_len) {
    /* 花指令：cmp xzr,xzr 永真，b.ne 永不跳，.word 迷惑反汇编器 */
    { volatile uint32_t _a = g_opaque; volatile uint32_t _b = g_opaque;
    __asm__ volatile(
        "cmp %w0, %w1\n\t"
        "b.eq 1f\n\t"
        ".word 0xDEADBEEF\n\t"
        "1:\n\t"
        :: "r"(_a), "r"(_b) : "cc"
    ); }
    adapt_cache_strategy();

    uint64_t s[4];
    memcpy(s, input, 25);
    memset((uint8_t *)s + 25, 0x5A, 7);  /* padding */

    /* 无分支蜜罐：正常 policy=3 → penalty=0 → rounds=12
     *             异常 policy=7 → penalty=4 → rounds=8   */
    int penalty = (g_cache_policy != 0x03u) * 4;
    int rounds  = 12 - penalty;

    for (int r = 0; r < rounds; r++) {
        s[0] = (ROR64(s[0], 8) + s[1]) ^ (uint64_t)r;
        s[1] = ROL64(s[1], 3) ^ s[0];
        s[2] = (ROR64(s[2], 8) + s[3]) ^ (uint64_t)(r + 4);
        s[3] = ROL64(s[3], 3) ^ s[2];
        s[0] ^= s[3];
        s[2] ^= s[1];
    }

    /* Squeeze：每次输出 32 字节，额外置换后继续 */
    int pos = 0;
    while (pos < out_len) {
        int chunk = (out_len - pos < 32) ? (out_len - pos) : 32;
        memcpy(out + pos, s, (size_t)chunk);
        pos += chunk;
        s[0] += s[2];
        s[1] ^= s[3];
        s[2]  = ROL64(s[2], 17);
        s[3]  = ROR64(s[3], 11);
    }
}

/* soKey 双向验证常量（XOR 加密存储，converge.py 填入） */
static volatile const uint32_t EXPECTED_SOKEY_CHECK_ENC = 0xb486524au;

/*
 * key_schedule — 从 flag + soKey 派生 runtime_params。
 * soKey 双向验证（无分支）：错误 soKey → delta 被 0xDEADBEEF 污染。
 */
void key_schedule(const uint8_t *flag, const uint8_t *so_key,
                  struct runtime_params *params) {
    uint8_t material[128];

    /* 1. ARX 扩展 96 字节 */
    expand_key_material(flag, material, 96);

    /* 2. soKey 混入 material[96:112] */
    for (int i = 0; i < 16; i++)
        material[96 + i] = material[i] ^ so_key[i];

    /* 3. IPC 混入 material[112:128]（可选层） */
    uint8_t ipc[16];
    get_ipc_material(ipc);
    for (int i = 0; i < 16; i++)
        material[112 + i] = material[32 + i] ^ ipc[i];

    /* 4. 派生 round_keys[16]：material[0:64] 每 4 字节一个 */
    for (int i = 0; i < 16; i++)
        params->round_keys[i] = *(uint32_t *)(material + i * 4);

    /* 5. 派生 configs[16]：material[64:80] 每字节拆 4 个 2-bit 字段 */
    for (int i = 0; i < 16; i++) {
        uint8_t b = material[64 + i];
        params->configs[i].sbox_selector  = (b >> 0) & 0x03u;
        params->configs[i].shift_pattern  = (b >> 2) & 0x03u;
        params->configs[i].mix_matrix_idx = (b >> 4) & 0x03u;
        params->configs[i].nonlinear_mode = (b >> 6) & 0x03u;
    }

    /* 6. 派生 sbox_seeds[4]：material[80:96] */
    for (int i = 0; i < 4; i++)
        params->sbox_seeds[i] = *(uint32_t *)(material + 80 + i * 4);

    /* 7. 派生 delta：material[96:100]（已混入 soKey） */
    params->delta = *(uint32_t *)(material + 96);

    /* 8. soKey 双向验证（无分支算术污染）
     *    正确 soKey → diff=0 → poison=0 → delta 不变
     *    错误 soKey → diff≠0 → poison=0xDEADBEEF → delta 被污染 */
    uint8_t cx_key[16];
    get_const_xor_key(cx_key);
    uint32_t sokey_check_dec = EXPECTED_SOKEY_CHECK_ENC ^ *(const uint32_t *)cx_key;
    uint32_t check  = params->round_keys[15] ^ *(const uint32_t *)(so_key + 12);
    uint32_t diff   = check ^ sokey_check_dec;
    uint32_t poison = ((diff | (~diff + 1u)) >> 31) * 0xDEADBEEFu;
    params->delta  ^= poison;

    /* 9. 蜜罐 F：Inline Hook 完整性检测（伪装为"内存池校验"）
     *    检测关键 libc 函数入口是否被 Frida/Xposed 篡改。
     *    ARM64 inline hook 特征：函数头被替换为 B/LDR+BR 跳转。
     *    正常函数头不会以 B (0x14/0x17) 或 LDR X16,[PC] (0x58) 开头。
     *    无分支：检测到 hook → delta 被额外污染。 */
    {
        uint32_t hook_score = 0;
        /* 通过 get_func_by_id 获取函数地址（无明文字符串） */
        void *targets[3];
        targets[0] = get_func_by_id(0);  /* clock_gettime */
        targets[1] = get_func_by_id(4);  /* open */
        targets[2] = get_func_by_id(7);  /* mprotect */
        for (int t = 0; t < 3; t++) {
            if (!targets[t]) continue;
            uint32_t insn = *(volatile uint32_t *)targets[t];
            uint32_t op = insn >> 26;
            hook_score += (op == 0x05 || op == 0x25);  /* B or BL */
            hook_score += ((insn >> 24) == 0x58);      /* LDR Xn,[PC] */
        }
        /* 无分支污染：hook_score > 0 → delta ^= 0xCAFECAFE */
        uint32_t hook_poison = (hook_score > 0) * 0xCAFECAFEu;
        params->delta ^= hook_poison;
    }
}
