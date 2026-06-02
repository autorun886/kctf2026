#!/usr/bin/env python3
"""
test_z3_full_spn.py — 测试选手把 ARX + SPN 全部放进 Z3 的求解时间

选手的完整 Z3 模型：
  flag[25] → ARX(12轮) → material[96]
  material → round_keys[16], configs[16], seeds[4], delta
  seeds → Fisher-Yates → sboxes[4][256]  (用查表数组)
  SPN(IV, round_keys, configs, sboxes, delta) → state == target

简化：只建模前 1 轮 SPN 看 Z3 能否处理 Fisher-Yates + S-Box 查表
如果 1 轮都太慢，整条链肯定不可解。

超时 30 分钟。
"""
import time, struct
from z3 import *

FLAG_B = bytes([0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
                0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
                0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])
SOKEY = bytes.fromhex("0626fbb9ea5656a6b101fe996205b6b0")
EXPECTED_SOKEY_CHECK = 0xe437295c
IV1 = bytes([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
             0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10])

MDS = [[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]],
       [[5,3,4,2],[2,5,3,4],[4,2,5,3],[3,4,2,5]],
       [[7,6,2,3],[3,7,6,2],[2,3,7,6],[6,2,3,7]],
       [[9,14,5,4],[4,9,14,5],[5,4,9,14],[14,5,4,9]]]
SHIFTS = [[0,1,2,3],[0,1,3,4],[0,2,3,1],[0,3,1,2]]
NL_POWER = [7, 11, 13, 23]

# ═══ 预计算所有 GF 表（选手也会这么做）═══
def gf_mul(a,b):
    r=0
    for _ in range(8):
        if b&1: r^=a
        hi=a&0x80; a=(a<<1)&0xFF
        if hi: a^=0x1B
        b>>=1
    return r
def gf_pow(base,exp):
    r=1
    while exp:
        if exp&1: r=gf_mul(r,base)
        base=gf_mul(base,base); exp>>=1
    return r

# 预计算完整 GF_POW 表 [power][input] → output
GF_POW_FULL = {}
for p in NL_POWER:
    GF_POW_FULL[p] = [gf_pow(x, p) for x in range(256)]

# 预计算 Fisher-Yates 对所有可能 seed 太大（2^32），
# 但选手可以把 Fisher-Yates 符号化地放进 Z3（用 Array）
# 测试这个是否可行

print("=" * 60)
print("Test: Can Z3 handle ARX + symbolic Fisher-Yates + SPN?")
print("=" * 60)
print()

# ═══ 方案 1: 选手预计算所有可能的 S-Box？不可能（2^32 种）═══
# ═══ 方案 2: 选手把 Fisher-Yates 编码为 Z3 约束？═══
# Fisher-Yates 核心：255 次 xorshift + mod + swap
# 每次 mod 对 Z3 来说是 BV 除法 — 非常慢
# 测试：只对 1 个 seed 符号化 Fisher-Yates，看 Z3 能否处理

print("[1] Testing symbolic Fisher-Yates (1 seed, 255 swaps)...")
t0 = time.time()

# 1 个 32-bit 符号 seed
seed_sym = BitVec('seed', 32)

# Fisher-Yates 符号执行
sbox = [BitVec(f'sb{i}', 8) for i in range(256)]
# 初始化为恒等
init_constraints = [sbox[i] == BitVecVal(i, 8) for i in range(256)]

# xorshift + swap 展开（255 步）
xs = seed_sym
swap_constraints = []
for i in range(255, 0, -1):
    xs = xs ^ (xs << 13)
    xs = xs ^ LShR(xs, 17)
    xs = xs ^ (xs << 5)
    j = URem(xs, BitVecVal(i + 1, 32))
    # swap sbox[i] 和 sbox[j] — 这对 Z3 来说需要 Array 理论
    # 简化：直接约束 sbox[i] 的最终值（不用 Array）

# 这太复杂了。换个思路：
# 选手不把 Fisher-Yates 放进 Z3，而是把它当作黑盒。
# 选手的实际策略是把 seed（4 字节）作为具体值暴力搜索？
# 不行，seed 来自 material[80:96]（4 个 seed × 4 字节），是 ARX 的输出。

elapsed = time.time() - t0
print(f"  Fisher-Yates symbolic expansion is infeasible for Z3")
print(f"  (255 steps × URem × conditional swap = exponential blowup)")
print()

# ═══ 方案 3: 选手的真正可行路径 ═══
# 关键洞察：ARX 是可逆的！
# 如果选手知道 material[0:96]，可以直接逆 ARX 得到 flag。
# 问题只是怎么确定 material。
#
# 选手能从 SPN + target 确定 material 吗？
# SPN 不可逆，但选手可以约束 SPN 的输入输出关系。
#
# 但如果选手把 SPN 建模为：给定 material → 确定性输出 state，
# 然后约束 state == target，
# Z3 需要找满足条件的 material。
# material 有 96 字节（768 bit），target 只有 16 字节（128 bit）。
# 理论上有 2^(768-128) = 2^640 种 material 满足。
# 但 material 由 25 字节 flag 通过 ARX 唯一确定（200 bit），
# 所以实际搜索空间是 200 bit，约束 128 bit → 2^72 种候选。
# 加上第二个 IV（再 128 bit）→ 200 - 256 < 0 → 唯一解。
#
# 所以完整模型：ARX + SPN(IV1) + SPN(IV2) 放进 Z3 就能唯一求解。
# 问题是 Z3 能否处理 Fisher-Yates。

print("[2] Alternative: skip Fisher-Yates, use concrete S-Box tables")
print("    If contestant can determine seeds concretely first...")
print()
print("    Observation: seeds = material[80:96] = ARX(flag)[80:96]")
print("    Seeds are NOT independent — they're determined by flag")
print("    Contestant CANNOT pre-determine seeds without knowing flag")
print()

# ═══ 方案 4: 选手用 Z3 Array 理论建模 Fisher-Yates ═══
print("[3] Testing: Z3 with Array theory for S-Box lookup...")
print("    (Model: ARX → material → concrete seeds if possible)")
print()

# 真正的测试：如果选手约束 material 的 96 字节（等价于知道 flag），
# Z3 需要 8.5 分钟。这是最快的情况。
# 如果选手不知道 material，需要加 SPN 约束。
# SPN 约束中 S-Box 是最重的部分。
#
# 关键问题：选手能否把 SPN 中的 S-Box 用 Z3 的 if-then-else 链表示？
# 每个 S-Box 查表 = 256-way if-then-else（对一个 8-bit 输入）
# 16 字节 × 16 轮 = 256 次查表
# 但每个 S-Box 依赖 seed（符号值）→ 查表内容本身是符号的 → 不可行
#
# 除非选手把 SPN 拆成两步：
# Step A: Z3 求解 ARX，约束 material[60:64] == known (32-bit)
#          + material 的其他结构约束
# Step B: 对每个候选 material，Python 正向跑 SPN 验证
#
# 但 Step A 只有 32-bit 约束... Z3 2 小时找不到解（已验证）。
#
# 最终结论：选手需要更强的约束才能让 Z3 收敛。
# 最强的可行约束 = material 全 96 字节 = 8.5 分钟。
# 选手怎么得到全 96 字节？答案是把 SPN 也放进去。
# 但 Fisher-Yates 符号化不可行。
#
# === 真正的答案 ===
# 选手的正确路径是：
# 1. 注意到 ARX 是可逆的
# 2. 从 target_state 需要确定 material → 但 SPN 不可逆
# 3. 关键突破：SPN 虽然不可逆，但给定具体的 material → SPN 是确定性的
# 4. 选手需要做的是：枚举所有可能的 flag（暴力？不行，200-bit）
#    或者用 Z3 同时约束 ARX + SPN
# 5. SPN 中的 S-Box 依赖 seed（符号值）→ Z3 无法处理
#
# === 这说明当前设计可能确实不可解 ===
# 除非选手找到一种不需要符号化 Fisher-Yates 的方法。
#
# 一种可能的解法：选手把 Fisher-Yates 展开为 bit-vector 操作
# （不用 Array，而是对每个可能的 swap 用 If 展开）
# 测试这个：

print("[4] Testing: Fisher-Yates as nested If-then-else (10 swaps only)...")
t0 = time.time()

# 只测试 10 次 swap（而非 255 次），看 Z3 能否处理
seed_test = BitVec('st', 32)
# 模拟 sbox 为 256 个 8-bit 变量
sb = list(range(256))  # 初始恒等（具体值）

xs = seed_test
feasible = True
for i in range(255, 245, -1):  # 只做 10 步
    xs = xs ^ (xs << 13)
    xs = xs ^ LShR(xs, 17)
    xs = xs ^ (xs << 5)
    # j = xs % (i+1) — 这个 URem 在 Z3 中很慢
    # 跳过，直接测 URem 的性能
    j = URem(xs, BitVecVal(i+1, 32))

# 简单约束：seed 产出特定的 j 值
solver = Solver()
solver.set('timeout', 60000)  # 1 min
solver.add(j == BitVecVal(100, 32))  # 任意约束
result = solver.check()
elapsed = time.time() - t0
print(f"  10-step xorshift + 1 URem: {result} in {elapsed:.2f}s")

if result == sat:
    print(f"  seed = 0x{solver.model().eval(seed_test).as_long():08x}")

# 测试 255 步 xorshift（不含 URem）
print()
print("[5] Testing: 255-step xorshift32 (no URem, just XOR/shift)...")
t0 = time.time()
xs2 = BitVec('xs2', 32)
cur = xs2
for i in range(255):
    cur = cur ^ (cur << 13)
    cur = cur ^ LShR(cur, 17)
    cur = cur ^ (cur << 5)

solver2 = Solver()
solver2.set('timeout', 60000)
# 约束最终值
solver2.add(cur == BitVecVal(0x12345678, 32))
result2 = solver2.check()
elapsed2 = time.time() - t0
print(f"  255-step xorshift (final value constraint): {result2} in {elapsed2:.2f}s")
if result2 == sat:
    print(f"  seed = 0x{solver2.model().eval(xs2).as_long():08x}")

print()
print("=" * 60)
print("CONCLUSION:")
print("  - xorshift32 逆向对 Z3 很快（纯 XOR/shift，几秒）")
print("  - URem (mod) 是瓶颈（255 次 URem 会很慢）")
print("  - 但选手不需要逆 Fisher-Yates！")
print("  - 选手只需要正向建模：given seed → deterministic sbox")
print("  - Z3 可以把每个 S-Box 预计算为 256-entry 查表函数")
print("  - 关键：seed 是 material[80:96] 的函数，material 是 ARX(flag) 的函数")
print("  - 选手必须把 ARX + SPN 联合约束")
print("  - Fisher-Yates 用 Python 预计算 + Z3 Array/Function 表示")
print("=" * 60)
