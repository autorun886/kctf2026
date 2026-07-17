#include <stdint.h>
#include <string.h>
#include "include/kctf.h"

/* ── 方案 A 全局状态（repair 系列函数修复，core_compute 使用）── */
uint8_t  sbox_shipped[256];       /* repair_sbox 修复 */
uint32_t xtea_delta       = 0x9E3779B9u; /* repair_constants 修复 */
uint32_t round_constants[32];     /* repair_constants 修复 */

/* step2/step3 参数（repair_semantics 修复） */
uint8_t  step2_amount = 0;        /* 循环左移量，低 5 bit 有效 */
uint32_t step3_param  = 0;        /* 非线性混合参数 */
uint8_t  step3_bits   = 16;       /* step3 有效位数，16~31 */

/* ── 硬编码 IV（方案 A）────────────────────────────────── */
static const uint32_t IV_A[4] = {
    0xDEADBEEFu, 0xCAFEBABEu, 0x8BADF00Du, 0xFEEDFACEu
};

/* const_xor piece 1: IV_A[0] ^ (IV_A[2] ror 13) — 耦合到 const_xor.c */
uint32_t cxk_get_piece1(void) {
    uint32_t v = IV_A[2];
    v = (v >> 13) | (v << 19);  /* ror 13 */
    return IV_A[0] ^ v;
}

/* ── step2：循环左移（repair_semantics 修复 amount）────── */
static inline uint32_t step2(uint32_t val, uint8_t amount) {
    amount &= 0x1Fu;
    if (amount == 0) return val;
    return (val << amount) | (val >> (32u - amount));
}

/* ── step3：非线性混合（repair_semantics 修复 param）───── */
static inline uint32_t step3(uint32_t state_val, uint32_t param) {
    uint32_t mask = (step3_bits < 32u) ? ((1u << step3_bits) - 1u) : 0xFFFFFFFFu;
    param &= mask;
    return state_val ^ ((state_val >> 5) + param) ^ ((state_val << 4) + (param >> 12));
}

/* ── 类 XTEA 单轮（使用 round_constants 而非固定 delta 累加）
 *
 *  标准 XTEA：sum += delta; v0 += ((v1<<4 ^ v1>>5) + v1) ^ (sum + key[sum&3])
 *  魔改版：用 round_constants[r] 替代 (sum + key[...])，
 *           并在 v1 路径插入 step2 + step3，使逆向更复杂。
 * ──────────────────────────────────────────────────────── */
static inline void xtea_round_fwd(uint32_t *v0, uint32_t *v1,
                                   uint32_t rc, uint32_t delta_acc) {
    /* v0 路径：标准 XTEA 结构 */
    *v0 += ((*v1 << 4) ^ (*v1 >> 5)) + *v1 ^ (delta_acc + rc);
    /* v1 路径：加入 step2 + step3 非线性 */
    uint32_t t = step2(*v0, step2_amount);
    *v1 += step3(t, rc) ^ (delta_acc + rc);
}

/*
 * BB0~BB7：每个 BB 执行 2 轮 xtea_round_fwd，共 16 轮。
 * state[4] = {v0, v1, v2, v3}，相邻对 (v0,v1) 和 (v2,v3) 独立 Feistel。
 *
 * 控制流破坏点（发布时）：
 *   BB0→BB1：B 指令 imm26 被 flag[0:4] XOR
 *   BB2→BB3：CSEL cond 被 flag[4] 低 4 bit XOR
 *   BB4→BB5：B 指令目标指向 dead block
 *   BB6→BB7：dispatch table 被 flag[5:9]^soKey[0:4] XOR
 *
 * 注意：函数内部不能有 switch/if 跳转到 BB 标签，
 * 必须用 goto 保持 BB 结构，让编译器生成真实的 B 指令。
 */
void core_compute(uint32_t state[4]) {
    uint32_t v0 = state[0] ^ IV_A[0];
    uint32_t v1 = state[1] ^ IV_A[1];
    uint32_t v2 = state[2] ^ IV_A[2];
    uint32_t v3 = state[3] ^ IV_A[3];
    uint32_t delta_acc = 0;

BB0:
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[0],  delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[1],  delta_acc);
    goto BB1;  /* 发布时此 B 指令的 imm26 被 XOR 破坏 */

BB1:
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[2],  delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[3],  delta_acc);
    /* BB1→BB2：正常跳转，不破坏 */
    goto BB2;

BB2:
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[4],  delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[5],  delta_acc);
    /* BB2→BB3：用内联汇编强制生成 TBZ 指令。
     * 正常路径：v0 bit0 = 1（由 IV_A[0]=0xDEADBEEF 保证），TBZ 不跳转，走 BB3。
     * 发布时破坏 TBZ 的 bit 字段（[22:19]），使其测试错误的 bit，
     * 导致条件判断错误，走错误路径（多加一次 delta）。 */
    __asm__ volatile(
        "tbz %w0, #0, 1f\n\t"   /* bit0=1 时不跳（正常路径） */
        "b   2f\n\t"             /* 正常路径：跳到 BB3 */
        "1:\n\t"                 /* 错误路径：多加一次 delta */
        "ldr w9, [%3]\n\t"
        "add %w2, %w2, w9\n\t"
        "2:\n\t"
        : "+r"(v0), "+r"(v1), "+r"(delta_acc)
        : "r"(&xtea_delta)
        : "w9"
    );

BB3:
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[6],  delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[7],  delta_acc);
    goto BB4;

BB4:
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[8],  delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[9],  delta_acc);
    /* BB4→BB5：发布时此 B 指令的 imm26 被替换为指向 dead block 的偏移。
     * 用内联汇编强制生成 B 指令，防止编译器把 goto 折叠进上一个 BB。 */
    __asm__ volatile("b 1f\n\t"          /* 正常路径：跳过 dead block */
                     /* dead block：合法但无意义，不崩溃但计算错误 */
                     "mov x9,  x9\n\t"
                     "mov x10, x10\n\t"
                     "mov x11, x11\n\t"
                     "mov x12, x12\n\t"
                     "1:\n\t"
                     ::: "x9","x10","x11","x12");

BB5:
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[10], delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[11], delta_acc);

BB6:
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[12], delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[13], delta_acc);
    /* BB6→BB7：dispatch table 间接跳转。
     * 用内联汇编强制生成 br x9，发布时 dispatch_table 中的偏移被加密。
     * 运行时 x9 = BB7 入口地址（repair_cfg 修复后正确）。 */
    {
        void *bb7_addr;
        __asm__ volatile(
            "adr %0, 2f\n\t"   /* 取 BB7 标签地址 */
            "br  %0\n\t"       /* 间接跳转（发布时此地址从 dispatch_table 加载） */
            "2:\n\t"
            : "=r"(bb7_addr)
            :
            :
        );
    }

BB7:
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[14], delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[15], delta_acc);
    /* 最后 4 轮用 sbox_shipped 做非线性混合 */
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[16], delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[17], delta_acc);
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[18], delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[19], delta_acc);
    /* S-Box 混入（repair_sbox 修复后才正确） */
    v0 ^= (uint32_t)sbox_shipped[v0 & 0xFF];
    v1 ^= (uint32_t)sbox_shipped[v1 & 0xFF];
    v2 ^= (uint32_t)sbox_shipped[v2 & 0xFF];
    v3 ^= (uint32_t)sbox_shipped[v3 & 0xFF];
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[20], delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[21], delta_acc);
    delta_acc += xtea_delta;
    xtea_round_fwd(&v0, &v1, round_constants[22], delta_acc);
    xtea_round_fwd(&v2, &v3, round_constants[23], delta_acc);

    state[0] = v0;
    state[1] = v1;
    state[2] = v2;
    state[3] = v3;
}
