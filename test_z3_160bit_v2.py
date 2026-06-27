#!/usr/bin/env python3
"""
test_z3_160bit_v2.py — 优化版：反推 squeeze 后直接约束 ARX 末态
关键优化：
  1. 从已知 material 字节反推 squeeze，得到 ARX 末态 s[0..3] 的部分已知 bits
  2. 用 64-bit BitVec 直接约束（避免 8-bit 碎片）
  3. 只让 Z3 处理 12 轮 ARX 核心，不穿透 squeeze
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

# ═══ 从 material 反推 ARX 末态 ═══
# Squeeze 结构：
#   material[0:32]  = s[0..3] 直接输出（第一轮 squeeze）
#   然后 s[0]+=s[2]; s[1]^=s[3]; s[2]=rol(s[2],17); s[3]=ror(s[3],11)
#   material[32:64] = 变换后的 s[0..3]（第二轮）
#   再变换一次
#   material[64:96] = 再次变换后的 s[0..3]（第三轮）
#
# 因此：material[0:32] 就是 ARX 末态的直接 dump！
# material[60:64] = 第二轮 squeeze 的 s'[3] 的 bytes[4:8]... 不对
#
# 让我重新算 offset：
#   Squeeze round 0: output material[0:32] = pack(s[0],s[1],s[2],s[3])
#   Squeeze round 1: s[0]+=s[2]; s[1]^=s[3]; s[2]=rol17; s[3]=ror11
#                    output material[32:64] = pack(s[0]',s[1]',s[2]',s[3]')
#   Squeeze round 2: s[0]'+=s[2]'; s[1]'^=s[3]'; s[2]'=rol17; s[3]'=ror11
#                    output material[64:96] = pack(s[0]'',s[1]'',s[2]'',s[3]'')
#
# 约束点：
#   material[60:64] → 在 squeeze round 1 输出中，offset 60-32=28 → s[3]' 的 bytes[4:8]
#     等等，s[3]' 是 8 字节，material[32:40]=s[0]', [40:48]=s[1]', [48:56]=s[2]', [56:64]=s[3]'
#     所以 material[60:64] = s[3]'[4:8] 即 s[3]' 的高 4 字节
#     不对：material[56:64] = s[3]'（8字节LE），material[60:64] = s[3]' 的 byte[4..7]
#
#   material[80:96] → squeeze round 2 输出，offset 80-64=16
#     material[64:72]=s[0]'', [72:80]=s[1]'', [80:88]=s[2]'', [88:96]=s[3]''
#     所以 material[80:88] = s[2]'' 的全部 8 字节
#     material[88:96] = s[3]'' 的全部 8 字节
#
# 策略：从 known seeds (material[80:96]) 得到 s[2]'' 和 s[3]''，
# 从 material[60:64] 得到 s[3]' 的部分字节。
# 然后反推 squeeze 链回到 ARX 末态 s[0..3]。
#
# 但问题是：我们不知道 s[0]'', s[1]'' 和 squeeze 1 的 s[0]', s[1]', s[2]'
# 所以无法完全反推。
#
# 换个思路：既然 material[0:32] = ARX 末态直接 dump，
# 如果我们有 material[0:32] 的任何字节，就能直接约束 ARX 末态。
# 但选手不知道 material[0:32]...
#
# 所以回到现实：选手能约束的只有 material[60:64] 和 material[80:96]，
# 这些都在 squeeze 后面，Z3 必须穿透 squeeze。
#
# 真正的优化：把约束表达为 64-bit 整体而非逐字节！

print("=" * 60)
print("  Z3 ARX Solver v2 — 64-bit constraints + tactics")
print(f"  ARX rounds: {ARX_ROUNDS}")
print("=" * 60)
print()

# ═══ 建模 ═══
print("[1/3] Building Z3 model (64-bit bitvectors)...", flush=True)
t0 = time.time()

# 用 4 个 64-bit 变量直接表示输入（更高效）
# flag[0:8] → s_in[0], flag[8:16] → s_in[1], flag[16:24] → s_in[2], flag[24]+pad → s_in[3]
# 但 flag 只有 25 字节，最后 7 字节是 0x5A 填充

# 直接用 200-bit 输入建模
flag_bv = BitVec('flag', 200)  # 25 bytes = 200 bits

# 分解为 4 × 64-bit 状态字
# buf[0:8] = flag[0:8], buf[8:16] = flag[8:16], buf[16:24] = flag[16:24]
# buf[24:32] = flag[24] + 0x5A*7

s0_init = Extract(63, 0, flag_bv)       # flag[0:8] LE
s1_init = Extract(127, 64, flag_bv)     # flag[8:16] LE
s2_init = Extract(191, 128, flag_bv)    # flag[16:24] LE

# s3: flag[24] 是 1 字节，后面 7 字节 0x5A
s3_init = ZeroExt(56, Extract(199, 192, flag_bv)) | BitVecVal(0x5A5A5A5A5A5A5A00, 64)
# 更正：小端，flag[24] 在 byte 0，0x5A 在 bytes 1-7
# s3 = flag[24] | (0x5A << 8) | (0x5A << 16) | ... | (0x5A << 56)
PAD_BYTES = 0
for i in range(1, 8):
    PAD_BYTES |= (0x5A << (i * 8))
s3_init = ZeroExt(56, Extract(199, 192, flag_bv)) | BitVecVal(PAD_BYTES, 64)

s = [s0_init, s1_init, s2_init, s3_init]

def z3_ror64(x, n):
    return LShR(x, n) | (x << (64 - n))
def z3_rol64(x, n):
    return (x << n) | LShR(x, 64 - n)

# 12 轮 ARX
for r in range(ARX_ROUNDS):
    s[0] = (z3_ror64(s[0], 8) + s[1]) ^ BitVecVal(r, 64)
    s[1] = z3_rol64(s[1], 3) ^ s[0]
    s[2] = (z3_ror64(s[2], 8) + s[3]) ^ BitVecVal(r + 4, 64)
    s[3] = z3_rol64(s[3], 3) ^ s[2]
    s[0] = s[0] ^ s[3]
    s[2] = s[2] ^ s[1]

# Squeeze round 0: material[0:32] = s[0..3]
# (无需输出，直接进入 squeeze 1)
sq = list(s)

# Squeeze permutation → squeeze 1 state
sq[0] = sq[0] + sq[2]
sq[1] = sq[1] ^ sq[3]
sq[2] = z3_rol64(sq[2], 17)
sq[3] = z3_ror64(sq[3], 11)
# material[32:64] = sq[0..3] → material[56:64] = sq[3]
# material[60:64] = sq[3] 的 bits [32:64]（即 byte 4~7）

# Squeeze permutation → squeeze 2 state
sq2 = list(sq)
sq2[0] = sq2[0] + sq2[2]
sq2[1] = sq2[1] ^ sq2[3]
sq2[2] = z3_rol64(sq2[2], 17)
sq2[3] = z3_ror64(sq2[3], 11)
# material[64:96] = sq2[0..3]
# material[80:88] = sq2[2], material[88:96] = sq2[3]

print(f"    Model build: {time.time()-t0:.1f}s")

# ═══ 约束 ═══
print("[2/3] Adding constraints (64-bit aligned)...", flush=True)

solver = Solver()
solver.set("timeout", 43200000)  # 12h

# 约束 1: material[80:96] == seeds (128 bits)
# material[80:88] = sq2[2] = KNOWN_SEEDS[0] | (KNOWN_SEEDS[1] << 32) (as uint64 LE)
seeds_q2 = KNOWN_SEEDS[0] | (KNOWN_SEEDS[1] << 32)
seeds_q3 = KNOWN_SEEDS[2] | (KNOWN_SEEDS[3] << 32)
solver.add(sq2[2] == BitVecVal(seeds_q2, 64))
solver.add(sq2[3] == BitVecVal(seeds_q3, 64))

# 约束 2: material[60:64] = sq[3] 的高 32 位
# material[56:64] = sq[3] (uint64 LE), material[60:64] = bytes 4-7 = bits[63:32]
sokey_12_16 = struct.unpack_from('<I', SOKEY, 12)[0]
target_rk15 = EXPECTED_SOKEY_CHECK ^ sokey_12_16
# rk15 = *(uint32*)(material+60) = sq[3] 的 bits[63:32]
solver.add(Extract(63, 32, sq[3]) == BitVecVal(target_rk15, 32))

print(f"    Constraints: 2×64-bit (seeds) + 1×32-bit (sokey_check) = 160 bits")
print()

# ═══ Solver tactics ═══
# 尝试用更高效的 tactic 组合
print("[3/3] Solving (tactic: qfbv → simplify → solve-eqs → bit-blast → sat)...", flush=True)

# 方法 A: 默认 solver
# 方法 B: 自定义 tactic pipeline
use_tactic = True

if use_tactic:
    t = Then(
        'simplify',
        'solve-eqs',
        'bit-blast',
        'sat'
    )
    solver2 = t.solver()
    solver2.set("timeout", 43200000)
    # 复制约束
    for c in solver.assertions():
        solver2.add(c)

    t1 = time.time()
    result = solver2.check()
    solve_time = time.time() - t1

    if result == sat:
        m = solver2.model()
    else:
        m = None
else:
    t1 = time.time()
    result = solver.check()
    solve_time = time.time() - t1
    m = solver.model() if result == sat else None

print()
print("=" * 60)
print(f"  Result: {result}")
print(f"  Solve time: {solve_time:.1f}s ({solve_time/60:.1f} min)")

if result == sat and m is not None:
    # 从 200-bit BitVec 提取 flag 字节
    flag_val = m.eval(flag_bv).as_long()
    flag_bytes = flag_val.to_bytes(25, 'little')
    print(f"  Solution: {flag_bytes.hex()}")
    print(f"  Expected: {FLAG_B_EXPECTED.hex()}")
    print(f"  Match: {flag_bytes == FLAG_B_EXPECTED}")
else:
    print(f"  No solution found")

print("=" * 60)
