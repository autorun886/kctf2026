#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/auxv.h>
#include "include/kctf.h"

/* ── GF(2^8) 内联（避免跨文件调用开销）────────────── */
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

static inline uint8_t gf_pow(uint8_t base, uint8_t exp) {
    uint8_t result = 1;
    while (exp > 0) {
        if (exp & 1) result = gf_mul(result, base);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    return result;
}

/* ── 蜜罐 D 全局变量（伪装为帧预算）────────────────── */
static volatile uint64_t g_frame_budget_ns = 16666666ULL;  /* 正常 = 16.6ms */

/* ── BRK 断点扫描（检测点 D）────────────────────────── */
static void calibrate_frame_budget(void) {
    extern char __executable_start;  /* linker symbol */
    uint32_t *code = (uint32_t *)&__executable_start;
    int brk_count = 0;
    for (int i = 0; i < 1024; i++) {
        /* ARM64 BRK 指令族：0xD4200000 掩码 */
        if ((code[i] & 0xFFE00000u) == 0xD4200000u)
            brk_count++;
    }
    g_frame_budget_ns = brk_count ? 8333333ULL : 16666666ULL;
}

/* ── 4 个 MDS 矩阵（GF(2^8)）────────────────────────── */
static const uint8_t MDS[4][4][4] = {
    {{0x02,0x03,0x01,0x01},{0x01,0x02,0x03,0x01},
     {0x01,0x01,0x02,0x03},{0x03,0x01,0x01,0x02}},
    {{0x05,0x03,0x04,0x02},{0x02,0x05,0x03,0x04},
     {0x04,0x02,0x05,0x03},{0x03,0x04,0x02,0x05}},
    {{0x07,0x06,0x02,0x03},{0x03,0x07,0x06,0x02},
     {0x02,0x03,0x07,0x06},{0x06,0x02,0x03,0x07}},
    {{0x09,0x0E,0x05,0x04},{0x04,0x09,0x0E,0x05},
     {0x05,0x04,0x09,0x0E},{0x0E,0x05,0x04,0x09}}
};

/* ── 4 种 ShiftRows 模式 ─────────────────────────────── */
static const uint8_t SHIFTS[4][4] = {
    {0,1,2,3}, {0,1,3,4}, {0,2,3,1}, {0,3,1,2}
};

/* ── 非线性幂次 ──────────────────────────────────────── */
static const uint8_t NL_POWER[4] = {7, 11, 13, 23};

/* ── apply_sbox（inline）────────────────────────────── */
static inline void apply_sbox(uint8_t *state, uint8_t sel,
                               uint8_t sboxes[4][256]) {
    for (int i = 0; i < 16; i++)
        state[i] = sboxes[sel][state[i]];
}

/* ── shift_rows（inline）────────────────────────────── */
static inline void shift_rows(uint8_t *state, const uint8_t shifts[4]) {
    uint8_t tmp[16];
    memcpy(tmp, state, 16);
    for (int row = 0; row < 4; row++) {
        uint8_t s = shifts[row] & 0x03u;
        for (int col = 0; col < 4; col++)
            state[row + 4 * col] = tmp[row + 4 * ((col + s) % 4)];
    }
}

/* ── mix_columns_mds ─────────────────────────────────── */
static void mix_columns_mds(uint8_t *state, const uint8_t matrix[4][4]) {
    for (int col = 0; col < 4; col++) {
        uint8_t in[4], out[4];
        for (int i = 0; i < 4; i++) in[i] = state[col * 4 + i];
        for (int i = 0; i < 4; i++) {
            out[i] = 0;
            for (int j = 0; j < 4; j++)
                out[i] ^= gf_mul(matrix[i][j], in[j]);
        }
        for (int i = 0; i < 4; i++) state[col * 4 + i] = out[i];
    }
}

/* ── add_round_key_full（inline）────────────────────── */
static inline void add_round_key_full(uint8_t *state, uint32_t round_key) {
    const uint8_t *k = (const uint8_t *)&round_key;
    for (int i = 0; i < 16; i++)
        state[i] ^= k[i % 4];
}

/* ── 蜜罐 B2：多时间点采样（伪装为性能计数器）──────── */
static volatile uint32_t g_perf_samples = 0;
static uint64_t g_last_sample_ns = 0;

static void sample_perf_counter(int round) {
    /* 每 4 轮采样一次，检测单步调试导致的时间膨胀 */
    if ((round & 3) != 0 || round == 0) return;
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    uint64_t now = (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
    if (g_last_sample_ns && (now - g_last_sample_ns) > 200000000ULL) {
        /* >200ms per 4 SPN rounds = 单步调试 */
        g_perf_samples++;
    }
    g_last_sample_ns = now;
}

/*
 * nonlinear_feedback — 伪装名：sm4_L_transform
 * 蜜罐 D（无分支折叠）：BRK 断点 → budget_flag=1 → 结果被污染。
 * 蜜罐 B2：多时间点采样 → perf_samples>0 → 额外污染。
 */
static void nonlinear_feedback(uint8_t *state, uint8_t mode,
                                uint32_t delta, int round) {
    __asm__ volatile(
        "cmp xzr, xzr\n\t"
        "b.eq 1f\n\t"
        ".word 0xFEEDFACE\n\t"
        "1:\n\t"
        ::: "cc"
    );
    if (round == 0) calibrate_frame_budget();
    sample_perf_counter(round);

    uint8_t power      = NL_POWER[mode & 0x03u];
    uint8_t round_const = (uint8_t)((delta >> ((round % 4) * 8)) & 0xFF);

    /* budget_flag = 0（正常）或 1（有断点） */
    uint8_t budget_flag = (g_frame_budget_ns < 16000000ULL) ? 1u : 0u;
    /* perf_flag = 0（正常）或 1（单步调试时间膨胀） */
    uint8_t perf_flag = (g_perf_samples > 2) ? 1u : 0u;
    /* 合并两个检测源 */
    uint8_t combined = budget_flag | perf_flag;

    for (int i = 0; i < 16; i++) {
        uint8_t x       = state[i] ^ round_const ^ (uint8_t)round;
        uint8_t correct = gf_pow(x, power);
        uint8_t simple  = x ^ power;                    /* 退化计算 */
        uint8_t poison  = combined * (correct ^ simple);
        state[i] = correct ^ poison;
    }
}

/*
 * spn_round — 单轮 SPN 变换。
 * 蜜罐 A（显式分支，选手突破口）：TracerPid≠0 → 走 AES 快速路径。
 * 后 4 轮（round>=12）：S-Box 选择依赖 state[0] 低 2 bit。
 */

/* 真正的 AES S-Box（蜜罐 A 使用） */
static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* g_render_mode 定义在 init.c，此处 extern */
extern volatile uint32_t g_render_mode;

static void spn_round(uint8_t *state, const struct round_config *cfg,
                      uint32_t round_key, uint32_t delta, int round,
                      uint8_t sboxes[4][256]) {
    __asm__ volatile(
        "cmp xzr, xzr\n\t"
        "b.eq 1f\n\t"
        ".word 0x8BADF00D\n\t"
        "1:\n\t"
        ::: "cc"
    );
    /* 蜜罐 A：TracerPid≠0 时走 AES 快速路径（显式分支，选手突破口） */
    if (__builtin_expect(g_render_mode, 0)) {
        for (int i = 0; i < 16; i++)
            state[i] = AES_SBOX[state[i]];
        /* 标准 AES ShiftRows {0,1,2,3} */
        shift_rows(state, SHIFTS[0]);
        /* 无 MixColumns → 结果微妙地错误 */
        const uint8_t *k = (const uint8_t *)&round_key;
        for (int i = 0; i < 16; i++) state[i] ^= k[i % 4];
        return;
    }

    /* S-Box 选择：前 8 轮静态，后 8 轮依赖 state[0] */
    uint8_t sbox_sel;
    if (round < 8) {
        sbox_sel = cfg->sbox_selector;
    } else {
        sbox_sel = (cfg->sbox_selector ^ state[0]) & 0x03u;
    }

    apply_sbox(state, sbox_sel, sboxes);
    shift_rows(state, SHIFTS[cfg->shift_pattern]);
    mix_columns_mds(state, MDS[cfg->mix_matrix_idx]);
    nonlinear_feedback(state, cfg->nonlinear_mode, delta, round);
    add_round_key_full(state, round_key);
}

/*
 * spn_encrypt — 16 轮 SPN 主循环。
 * 后 8 轮（round>=8）：dynamic_key ^= state[0:4]（轮密钥动态反馈）。
 * 蜜罐 E（无分支）：Unicorn 模拟执行缺少 HWCAP → round_key 被污染。
 */

/* ── 蜜罐 E：环境指纹（伪装为 NEON 加速路径选择）──── */
static volatile uint32_t g_hwcap_mask = 0;
static int g_hwcap_checked = 0;

static void select_simd_path(void) {
    /* 读取 AT_HWCAP 通过 getauxval（Android NDK 提供）
     * 真机 ARM64 至少有 HWCAP_FP|HWCAP_ASIMD = 0x3
     * Unicorn 默认 getauxval 返回 0 */
    unsigned long hwcap = getauxval(16);  /* AT_HWCAP = 16 */
    g_hwcap_mask = ((hwcap & 0x3) == 0x3) ? 0 : 0x5A5A5A5Au;
}

/* ── 蜜罐 A2：持续 TracerPid 检测（伪装为"渲染帧同步"）── */
static uint32_t check_render_sync(void) {
    char buf[512];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    /* 找 "TracerPid:" 后的数字 */
    const char *p = buf;
    const char *end = buf + n;
    while (p < end - 10) {
        if (p[0]=='T' && p[1]=='r' && p[2]=='a' && p[3]=='c' &&
            p[4]=='e' && p[5]=='r' && p[6]=='P' && p[7]=='i' && p[8]=='d') {
            p += 10;
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            int val = 0;
            while (p < end && *p >= '0' && *p <= '9') { val = val*10 + (*p-'0'); p++; }
            return (val != 0) * 0xA5A5A5A5u;
        }
        p++;
    }
    return 0;
}

/* ── 反符号执行/反 Unicorn：中间状态 CRC 混入 ──────────
 * 在第 8 轮结束后对 state 做 CRC32，结果混入后续 round_key。
 *
 * 对 Unicorn 的影响：
 *   选手用 Unicorn 模拟 spn_encrypt 时，必须确保前 8 轮的
 *   所有依赖（S-Box、MDS、round_key、delta）完全正确，
 *   否则第 8 轮 state 错误 → CRC 错误 → 后 8 轮全部错误。
 *   这迫使选手要么完整正确模拟整个 pipeline（等价于手写求解器），
 *   要么放弃 Unicorn 转向纯静态分析。
 *
 * 对 Z3 求解的影响：
 *   选手用 Z3 建模时，CRC32 可以展开为 bit-vector 约束
 *   （16 字节 × 2 次半字节查表 = 32 次查表，每次 16 种可能）。
 *   增加约束规模但不改变可解性。
 */
static uint32_t state_checksum(const uint8_t *state) {
    static const uint32_t crc_table[16] = {
        0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
        0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
        0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
        0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
    };
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < 16; i++) {
        crc ^= state[i];
        crc = (crc >> 4) ^ crc_table[crc & 0x0F];
        crc = (crc >> 4) ^ crc_table[crc & 0x0F];
    }
    return crc ^ 0xFFFFFFFF;
}

void spn_encrypt(uint8_t *state, const struct runtime_params *params,
                 uint8_t sboxes[4][256]) {
    if (!g_hwcap_checked) {
        select_simd_path();
        g_hwcap_checked = 1;
    }

    /* 重置 B2 时间采样状态（每次 nativeProcessInput 调用独立） */
    g_perf_samples = 0;
    g_last_sample_ns = 0;

    /* 蜜罐 A2：SPN 入口检测 TracerPid（覆盖 .so 加载后 attach 的场景） */
    uint32_t tracer_poison = check_render_sync();

    /* 反 Unicorn：第 8 轮后的 state CRC 混入后续 round_key */
    uint32_t state_crc_mix = 0;

    for (int round = 0; round < SPN_ROUNDS; round++) {
        if (round == 8) {
            state_crc_mix = state_checksum(state);
        }

        uint32_t dynamic_key = params->round_keys[round] ^ g_hwcap_mask ^ tracer_poison;
        if (round >= 8) {
            dynamic_key ^= *(const uint32_t *)&state[0];
            dynamic_key ^= state_crc_mix;
        }
        spn_round(state, &params->configs[round],
                  dynamic_key, params->delta, round, sboxes);
    }
}
