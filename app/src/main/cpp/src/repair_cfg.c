#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>
#include "include/kctf.h"

/* ── extern：全局状态定义在 core_compute.c ──────────── */
extern uint8_t  sbox_shipped[256];
extern uint32_t xtea_delta;

/* ── 合法 BB 入口偏移表（converge.py 自动填入）──────── */
/* ── BB 偏移（相对 .text 起始，converge.py 自动填入）── */
/* volatile const → .rodata，不影响 .text CRC */
static volatile const uint32_t BB0_BRANCH_OFF = 0x4870u;
static volatile const uint32_t BB1_OFF        = 0x4874u;
static volatile const uint32_t BB6_ADR_OFF_V  = 0x4af0u;
static volatile const uint32_t BB7_ENTRY_OFF  = 0x4af8u;
static volatile const uint32_t BB4_BRANCH_OFF = 0x4a3cu;
static volatile const uint32_t BB5_OFF        = 0x4a50u;
static volatile const uint32_t DEAD_BLOCK_OFF = 0x4a40u;

/* dispatch table（BB6→BB7 间接跳转，验证用） */
uint32_t dispatch_table[4] = {0,0,0,0};

/*
 * repair_cfg — 验证控制流修复参数。
 *
 * 不实际修改 .text（Android 12+ APK 内嵌加载不允许 mprotect RWX）。
 * 改为纯计算验证：从 flag 字节计算出预期跳转目标，与已知 BB 地址比对。
 * core_compute 中的指令由编译器正确生成，无需运行时修复。
 *
 * flag 布局：
 *   [0:4]  BB0→BB1 imm26 XOR key（正确值 = (BB1_OFF - BB0_BRANCH_OFF) / 4）
 *   [4]    BB2 TBZ bit field（低 4 bit，正确值 = 0x01）
 *   [5:9]  BB4→BB5 imm26 XOR key
 *   [9:13] BB6 adr imm21 XOR key（与 soKey[0:4] 联合）
 */
void repair_cfg(const uint8_t *flag, const uint8_t *so_key) {
    { volatile uint32_t _a = g_opaque; volatile uint32_t _b = g_opaque;
    __asm__ volatile(
        "cmp %w0, %w1\n\t"
        "b.eq 1f\n\t"
        ".word 0xABCD1234\n\t"
        "1:\n\t"
        :: "r"(_a), "r"(_b) : "cc"
    ); }

    /* ── 1. 验证 flag[0:4]：BB0→BB1 跳转偏移 ──────────── */
    uint32_t flag_imm26 = (*(const uint32_t *)flag) & 0x03FFFFFFu;
    int32_t  expected_imm26 = (int32_t)(BB1_OFF - BB0_BRANCH_OFF) / 4;
    if (flag_imm26 != (uint32_t)(expected_imm26 & 0x03FFFFFF))
        goto honeypot_sbox;

    /* ── 2. 验证 flag[4]：TBZ bit field ───────────────── */
    /* 正确值：bit#0（测试 v0 的 bit 0），编码为 0x01 */
    if ((flag[4] & 0x0Fu) != 0x01u)
        goto honeypot_sbox;

    /* ── 3. 验证 flag[5:9]：BB4→BB5 跳转偏移（与 soKey[8:12] 绑定）── */
    /* flag[5:9] ^ soKey[8:12] 必须等于 (BB5-DEAD)/4 ^ (DEAD-BB4)/4
     * 选手需追踪 EOR + .rodata 交叉引用 */
    uint32_t flag_b4 = *(const uint32_t *)(flag + 5) ^ *(const uint32_t *)(so_key + 8);
    uint32_t expected_b4 = ((BB5_OFF - DEAD_BLOCK_OFF) / 4u)
                         ^ ((DEAD_BLOCK_OFF - BB4_BRANCH_OFF) / 4u);
    if (flag_b4 != expected_b4) goto honeypot_sbox;

    /* ── 4. 验证 flag[9:13]：BB6 adr imm21（与 soKey 联合）── */
    uint32_t adr_key = *(const uint32_t *)(flag + 9) ^ *(const uint32_t *)so_key;
    /* 正确的 adr_key 应该使 BB6 的 adr 指向 BB7 入口
     * imm21 = BB7_ENTRY_OFF - BB6_ADR_OFF_V */
    int32_t expected_imm21 = (int32_t)(BB7_ENTRY_OFF - BB6_ADR_OFF_V);
    /* adr 编码：immlo = imm21[1:0], immhi = imm21[20:2] */
    uint32_t expected_adr_bits = (((uint32_t)expected_imm21 & 0x3u) << 29) |
                                 ((((uint32_t)expected_imm21 >> 2) & 0x7FFFFu) << 5);
    uint32_t imm_mask = (0x3u << 29) | (0x7FFFFu << 5);
    if ((adr_key & imm_mask) != expected_adr_bits)
        goto honeypot_delta;

    /* ── 5. 设置 dispatch_table[0] 供 repair_sbox 使用 ── */
    dispatch_table[0] = BB6_ADR_OFF_V;
    return;

honeypot_sbox:
    for (int i = 0; i < 256; i++) sbox_shipped[i] = (uint8_t)i;
    return;

honeypot_delta:
    xtea_delta = 0x9E3779B8u;
    return;
}
