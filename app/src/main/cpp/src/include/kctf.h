#pragma once
#include <stdint.h>
#include <stddef.h>

/* ── 共享常量 ─────────────────────────────────────────── */
#define FLAG_LEN        50   /* 50 字节交错输入：偶数位→方案A，奇数位→方案B */
#define FLAG_HALF       25   /* 每方案 25 字节 */
#define STATE_LEN       16
#define SOKEY_LEN       16

/* ── 方案 B：SPN 参数 ─────────────────────────────────── */
#define SPN_ROUNDS      16
#define SPN_SBOXES      4
#define SPN_MDS_COUNT   4
#define SPN_SHIFT_COUNT 4

struct round_config {
    uint8_t sbox_selector;   /* 2 bit */
    uint8_t shift_pattern;   /* 2 bit */
    uint8_t mix_matrix_idx;  /* 2 bit */
    uint8_t nonlinear_mode;  /* 2 bit */
};

struct runtime_params {
    uint32_t round_keys[SPN_ROUNDS];
    struct round_config configs[SPN_ROUNDS];
    uint32_t sbox_seeds[SPN_SBOXES];
    uint32_t delta;
};

/* ── 方案 B 函数声明 ──────────────────────────────────── */
void expand_key_material(const uint8_t *input, uint8_t *out, int out_len);
void key_schedule(const uint8_t *flag, const uint8_t *so_key,
                  struct runtime_params *params);
extern volatile uint32_t g_java_archive_profile_delta;
void generate_sbox(uint32_t seed, uint8_t sbox[256]);
void spn_encrypt(uint8_t *state, const struct runtime_params *params,
                 uint8_t sboxes[SPN_SBOXES][256]);

/* ── 方案 A 函数声明 ──────────────────────────────────── */
void core_compute(uint32_t state[4]);
void repair_cfg(const uint8_t *flag, const uint8_t *so_key);
void repair_sbox(const uint8_t *flag, uint8_t cfg_dependency);
void repair_constants(const uint8_t *flag, uint8_t sbox_first);
void repair_semantics(const uint8_t *flag, uint8_t rc_high4);

/* ── 共享工具 ─────────────────────────────────────────── */
void get_ipc_material(uint8_t out[16]);
void secure_bzero(void *ptr, size_t len);
uint32_t kctf_crc32(const uint8_t *data, size_t len);
uint32_t kctf_runtime_text_crc(uint32_t text_off, uint32_t text_size);
uint32_t kctf_guard_anchor(void);
void *get_func(const char *name);
void *get_func_by_id(int id);   /* 0=clock_gettime 1=fopen 2=fgets 3=fclose
                                    4=open 5=read 6=close 7=mprotect
                                    8=mmap 9=munmap */
const char *get_string(int id);

/* ── Seeds Oracle（mmap shellcode 反检测 + material 暴露）── */
int get_oracle_material(uint8_t out[32]);

/* 不透明谓词（nativeProcessInput 入口写入 flag[0]，花指令用此做条件） */
extern volatile uint32_t g_opaque;
uint32_t kctf_honey_bait_gate(uint32_t tag, uint32_t mix);
uint32_t kctf_real_bait_false_gate(uint32_t tag, uint32_t mix);
uint32_t kctf_bait_zero_mask(uint32_t tag, uint32_t mix);
uint64_t kctf_honey_q46_bridge(uint64_t lane, uint64_t mask,
                               uint32_t lane_ctx, uint8_t a_share);

/*
 * 动态 BR 蜜罐跳板：多处真实算法函数内使用。
 * tag/mix 进入共享 bait bus，使多个函数看起来存在状态传递；clean path
 * gate 返回非 0，跳过 br。若错误地把 gate 当检测失败路径，会落入纯蜜罐。
 */
#define KCTF_HONEY_BR_BAIT(tag_, mix_) do {                                \
    volatile uint32_t _hb_gate =                                            \
        kctf_honey_bait_gate((uint32_t)(tag_), (uint32_t)(mix_));           \
    __asm__ volatile(                                                       \
        "cbnz %w0, 7777f\n\t"                                               \
        "adrp x16, honey_lattice_oracle_path\n\t"                           \
        "add x16, x16, :lo12:honey_lattice_oracle_path\n\t"                 \
        "br x16\n\t"                                                        \
        "7777:\n\t"                                                         \
        :: "r"(_hb_gate) : "x16", "cc", "memory"                          \
    );                                                                      \
} while (0)

#define KCTF_HONEY_BR_BAIT_TBZ(tag_, mix_) do {                            \
    volatile uint32_t _hb_gate =                                            \
        kctf_honey_bait_gate((uint32_t)(tag_), (uint32_t)(mix_));           \
    __asm__ volatile(                                                       \
        "tbnz %w0, #0, 7777f\n\t"                                           \
        "adrp x16, honey_lattice_oracle_path\n\t"                           \
        "add x16, x16, :lo12:honey_lattice_oracle_path\n\t"                 \
        "br x16\n\t"                                                        \
        "7777:\n\t"                                                         \
        :: "r"(_hb_gate) : "x16", "cc", "memory"                          \
    );                                                                      \
} while (0)

#define KCTF_HONEY_BR_BAIT_CSEL(tag_, mix_) do {                           \
    volatile uint32_t _hb_gate =                                            \
        kctf_honey_bait_gate((uint32_t)(tag_), (uint32_t)(mix_));           \
    __asm__ volatile(                                                       \
        "adrp x16, honey_lattice_oracle_path\n\t"                           \
        "add x16, x16, :lo12:honey_lattice_oracle_path\n\t"                 \
        "adr x17, 7777f\n\t"                                                \
        "cmp %w0, #0\n\t"                                                   \
        "csel x16, x17, x16, ne\n\t"                                        \
        "br x16\n\t"                                                        \
        "7777:\n\t"                                                         \
        :: "r"(_hb_gate) : "x16", "x17", "cc", "memory"                  \
    );                                                                      \
} while (0)

/*
 * 动态恒假真实目标跳板：状态流和 honey bait 共用 bait bus，但 clean path
 * gate 返回 0，跳过 br。静态上会看到可能 br 到真实算法符号。
 */
#define KCTF_REAL_BR_FALSE_BAIT(tag_, mix_, target_) do {                  \
    volatile uint32_t _rb_gate =                                            \
        kctf_real_bait_false_gate((uint32_t)(tag_), (uint32_t)(mix_));      \
    __asm__ volatile(                                                       \
        "cbz %w0, 7788f\n\t"                                                \
        "adrp x16, " #target_ "\n\t"                                        \
        "add x16, x16, :lo12:" #target_ "\n\t"                              \
        "br x16\n\t"                                                        \
        "7788:\n\t"                                                         \
        :: "r"(_rb_gate) : "x16", "cc", "memory"                           \
    );                                                                      \
} while (0)

#define KCTF_REAL_BR_FALSE_BAIT_TBZ(tag_, mix_, target_) do {              \
    volatile uint32_t _rb_gate =                                            \
        kctf_real_bait_false_gate((uint32_t)(tag_), (uint32_t)(mix_));      \
    __asm__ volatile(                                                       \
        "tbz %w0, #0, 7788f\n\t"                                            \
        "adrp x16, " #target_ "\n\t"                                        \
        "add x16, x16, :lo12:" #target_ "\n\t"                              \
        "br x16\n\t"                                                        \
        "7788:\n\t"                                                         \
        :: "r"(_rb_gate) : "x16", "cc", "memory"                           \
    );                                                                      \
} while (0)

#define KCTF_REAL_BR_FALSE_BAIT_CSEL(tag_, mix_, target_) do {             \
    volatile uint32_t _rb_gate =                                            \
        kctf_real_bait_false_gate((uint32_t)(tag_), (uint32_t)(mix_));      \
    __asm__ volatile(                                                       \
        "adrp x16, " #target_ "\n\t"                                        \
        "add x16, x16, :lo12:" #target_ "\n\t"                              \
        "adr x17, 7788f\n\t"                                                \
        "cmp %w0, #0\n\t"                                                   \
        "csel x16, x17, x16, eq\n\t"                                        \
        "br x16\n\t"                                                        \
        "7788:\n\t"                                                         \
        :: "r"(_rb_gate) : "x16", "x17", "cc", "memory"                   \
    );                                                                      \
} while (0)
