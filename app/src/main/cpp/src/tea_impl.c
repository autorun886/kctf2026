#include <stdint.h>
#include "include/kctf.h"

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
