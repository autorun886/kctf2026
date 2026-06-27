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
void *get_func(const char *name);
void *get_func_by_id(int id);   /* 0=clock_gettime 1=fopen 2=fgets 3=fclose
                                    4=open 5=read 6=close 7=mprotect */
const char *get_string(int id);

/* ── Seeds Oracle（mmap shellcode 反检测 + material 暴露）── */
int get_oracle_material(uint8_t out[32]);

/* 不透明谓词（nativeProcessInput 入口写入 flag[0]，花指令用此做条件） */
extern volatile uint32_t g_opaque;
