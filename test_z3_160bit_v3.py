#!/usr/bin/env python3
"""
test_z3_160bit_v3.py — 架构级优化

核心思路：
  约束落在 squeeze 第 2/3 轮输出上（material[60:64] 和 material[80:96]），
  Z3 需要穿透 ARX 12轮 + squeeze 2~3轮 = 表达式极深。

  优化：手动反推 squeeze，把约束直接放在 ARX 末态 s[0..3] 上。

  分析 squeeze 结构：
    ARX 输出 = (a, b, c, d)  各 64-bit

    Squeeze 0 输出 material[0:32]:  直接 = (a, b, c, d)
    变换: a' = a+c, b' = b^d, c' = rol(c,17), d' = ror(d,11)

    Squeeze 1 输出 material[32:64]: = (a', b', c', d')
    变换: a'' = a'+c', b'' = b'^d', c'' = rol(c',17), d'' = ror(d',11)

    Squeeze 2 输出 material[64:96]: = (a'', b'', c'', d'')

  已知：
    material[80:88] = c'' (64-bit)  → seeds[0..1]
    material[88:96] = d'' (64-bit)  → seeds[2..3]
    material[60:64] = d' 的高32位   → rk15

  反推到 ARX 末态 (a, b, c, d)：
    c'' = rol(c', 17) = rol(rol(c, 17), 17) = rol(c, 34) = rol(c, 34 mod 64) = rol(c, 34)
    d'' = ror(d', 11) = ror(ror(d, 11), 11) = ror(d, 22)

    d' = ror(d, 11)
    d'的高32位已知 → ror(d,11)[63:32] 已知 → d 的部分 bits 已知

  所以：
    c = ror(c'', 34)  → 完全已知！(64 bits)
    d = rol(d'', 22)  → 完全已知！(64 bits) ...等等不对

  d'' = ror(d', 11)，d' = ror(d, 11) → d'' = ror(d, 22) → d = rol(d'', 22)

  但 d' = b ^ d... 不对！

  让我重新推导：
    Squeeze 变换是：a' = a+c; b' = b^d; c' = rol(c,17); d' = ror(d,11)

    所以 d' = ror(d, 11)，NOT involving other variables!
    c' = rol(c, 17)

    第二次：a'' = a'+c'; b'' = b'^d'; c'' = rol(c',17); d'' = ror(d',11)
    c'' = rol(c', 17) = rol(rol(c, 17), 17) = rol(c, 34)
    d'' = ror(d', 11) = ror(ror(d, 11), 11) = ror(d, 22)

  这意味着：
    已知 c'' → c = ror(c'', 34) = rol(c'', 30)  ← 完全确定 64 bits
    已知 d'' → d = rol(d'', 22)                   ← 完全确定 64 bits
    已知 d'[63:32] → ror(d,11)[63:32]            ← 已包含在 d 已知中

  太好了！从 seeds 可以直接反推出 ARX 末态的 c 和 d（共 128 bits）！
  再加上 rk15 约束（material[60:64] = d'[32:64]）也是 d 的函数，无需额外约束。

  总结：选手真正的约束是 ARX 12 轮输出的 s[2] 和 s[3] 完全已知（128 bits on 200-bit input）。
  Z3 只需处理纯 ARX 12 轮，无 squeeze！
"""
import struct, time
from z3 import *

# ═══ 已知常量 ═══
SOKEY = bytes.fromhex('0626fbb9ea5656a6b101fe996205b6b0')
KNOWN_SEEDS = [0x24be739f, 0x966cdda1, 0xbb2307b9, 0xc9fdcda7]
EXPECTED_SOKEY_CHECK = 0x5edb38bb
ARX_ROUNDS = 12

FLAG_B_EXPECTED = bytes([
    0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
    0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
    0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])

def ror64(x, n): return ((x >> n) | (x << (64 - n))) & ((1 << 64) - 1)
def rol64(x, n): return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)

# ═══ 从 material[80:96] 反推 ARX 末态的 s[2], s[3] ═══
# c'' = material[80:88] (LE uint64) = rol(c, 34) → c = ror(c'', 34) = rol(c'', 30)
# d'' = material[88:96] (LE uint64) = ror(d, 22) → d = rol(d'', 22)

c_double_prime = KNOWN_SEEDS[0] | (KNOWN_SEEDS[1] << 32)  # material[80:88]
d_double_prime = KNOWN_SEEDS[2] | (KNOWN_SEEDS[3] << 32)  # material[88:96]

target_s2 = rol64(c_double_prime, 30)  # ARX 末态 s[2]
target_s3 = rol64(d_double_prime, 22)  # ARX 末态 s[3]

# 验证：用已知 flag 正向算一下
def expand_arx_state(flag_bytes):
    buf = bytearray(32)
    buf[:25] = flag_bytes; buf[25:] = b'\x5A' * 7
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(ARX_ROUNDS):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1<<64)-1); s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1<<64)-1); s[2] ^= (r+4)
        s[3] = rol64(s[3], 3) ^ s[2]
        s[0] ^= s[3]; s[2] ^= s[1]
    return s

ref_state = expand_arx_state(FLAG_B_EXPECTED)
print("=" * 60)
print("  Pre-check: reverse squeeze derivation")
print(f"  target_s2 = 0x{target_s2:016x}")
print(f"  actual_s2 = 0x{ref_state[2]:016x}  {'✓' if target_s2 == ref_state[2] else '✗ MISMATCH'}")
print(f"  target_s3 = 0x{target_s3:016x}")
print(f"  actual_s3 = 0x{ref_state[3]:016x}  {'✓' if target_s3 == ref_state[3] else '✗ MISMATCH'}")
print("=" * 60)
print()

if target_s2 != ref_state[2] or target_s3 != ref_state[3]:
    print("ERROR: squeeze reversal incorrect, aborting")
    exit(1)

# ═══ 也可以加上 rk15 约束 → material[60:64] ═══
# material[60:64] 在 squeeze 1 输出中
# squeeze 1: d' = ror(d, 11) → material[56:64] = d' (全 8 字节)
# material[60:64] = d'[32:64] = ror(d, 11) 的高 32 位
# d 已知 → d' 也完全已知，可以做交叉验证
d_prime = ror64(target_s3, 11)
rk15_from_d = (d_prime >> 32) & 0xFFFFFFFF

sokey_12_16 = struct.unpack_from('<I', SOKEY, 12)[0]
target_rk15 = EXPECTED_SOKEY_CHECK ^ sokey_12_16
print(f"  rk15 from d': 0x{rk15_from_d:08x}")
print(f"  rk15 target:  0x{target_rk15:08x}  {'✓' if rk15_from_d == target_rk15 else '(independent constraint)'}")
print()

# ═══ Z3 建模：约束 ARX 末态的 s[2] 和 s[3] ═══
print("[1/3] Building Z3 model (pure ARX, no squeeze)...", flush=True)
t0 = time.time()

# 200-bit 输入
flag_bv = BitVec('flag', 200)

# 分解为 4×64-bit 初始状态（小端）
s0 = Extract(63, 0, flag_bv)
s1 = Extract(127, 64, flag_bv)
s2 = Extract(191, 128, flag_bv)
# s3: flag[24] (8 bits) + 0x5A×7
PAD = 0
for i in range(1, 8):
    PAD |= (0x5A << (i * 8))
s3 = ZeroExt(56, Extract(199, 192, flag_bv)) | BitVecVal(PAD, 64)

s = [s0, s1, s2, s3]

def z3_ror64(x, n):
    return LShR(x, n) | (x << (64 - n))
def z3_rol64(x, n):
    return (x << n) | LShR(x, 64 - n)

# 12 轮 ARX（Z3 只需处理这个）
for r in range(ARX_ROUNDS):
    s[0] = (z3_ror64(s[0], 8) + s[1]) ^ BitVecVal(r, 64)
    s[1] = z3_rol64(s[1], 3) ^ s[0]
    s[2] = (z3_ror64(s[2], 8) + s[3]) ^ BitVecVal(r + 4, 64)
    s[3] = z3_rol64(s[3], 3) ^ s[2]
    s[0] = s[0] ^ s[3]
    s[2] = s[2] ^ s[1]

print(f"    Build time: {time.time()-t0:.2f}s")

# ═══ 约束：s[2] == target, s[3] == target ═══
print("[2/3] Adding constraints (128-bit on ARX output, no squeeze)...", flush=True)

# 方法 A: 默认 solver
solver = Solver()
solver.set("timeout", 43200000)  # 12h
solver.add(s[2] == BitVecVal(target_s2, 64))
solver.add(s[3] == BitVecVal(target_s3, 64))

# 可选：加 rk15 约束（如果 rk15 不是 d 的冗余推导）
# material[60:64] 来自 squeeze1 的 d'[32:64] → 这是 s[3] 的函数
# 但如果上面的 check 已经 ✓ 说明它是冗余的，不加也行
# 如果 ✗ 说明它是独立的 32 bits，加上能帮助 Z3
if rk15_from_d != target_rk15:
    # 加独立约束：material[60:64]
    # d' = ror(s[3], 11), 取 bits[63:32]
    d_prime_sym = z3_ror64(s[3], 11)
    solver.add(Extract(63, 32, d_prime_sym) == BitVecVal(target_rk15, 32))
    print(f"    Added extra rk15 constraint (32 bits)")
    total_bits = 160
else:
    total_bits = 128
    print(f"    rk15 is redundant with s[3] (no extra constraint needed)")

print(f"    Total effective constraint: {total_bits} bits on 200-bit input")
print()

# ═══ 求解 ═══
print("[3/3] Solving...", flush=True)
t1 = time.time()
result = solver.check()
solve_time = time.time() - t1

print()
print("=" * 60)
print(f"  Result: {result}")
print(f"  Solve time: {solve_time:.1f}s ({solve_time/60:.1f} min)")

if result == sat:
    m = solver.model()
    flag_val = m.eval(flag_bv).as_long()
    flag_bytes = flag_val.to_bytes(25, 'little')
    print(f"  Solution: {flag_bytes.hex()}")
    print(f"  Expected: {FLAG_B_EXPECTED.hex()}")
    print(f"  Match: {flag_bytes == FLAG_B_EXPECTED}")

    # 正向验证
    check_state = expand_arx_state(flag_bytes)
    print(f"  Verify s[2]: {'✓' if check_state[2] == target_s2 else '✗'}")
    print(f"  Verify s[3]: {'✓' if check_state[3] == target_s3 else '✗'}")
else:
    print(f"  No solution found")

print("=" * 60)
