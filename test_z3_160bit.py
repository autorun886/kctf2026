#!/usr/bin/env python3
"""
test_z3_160bit.py — 测试 160-bit 约束下 Z3 能否解出 flag_B
选手视角：已知 seeds[4] + EXPECTED_SOKEY_CHECK，约束 ARX 12 轮
"""
import struct, time
from z3 import *

# ═══ 已知常量（选手逆向得到）═══
SOKEY = bytes.fromhex('0626fbb9ea5656a6b101fe996205b6b0')
KNOWN_SEEDS = [0x24be739f, 0x966cdda1, 0xbb2307b9, 0xc9fdcda7]
EXPECTED_SOKEY_CHECK = 0x5edb38bb
ARX_ROUNDS = 12

# 预期答案（用于验证）
FLAG_B_EXPECTED = bytes([
    0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
    0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
    0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])

# ═══ Z3 ARX 建模 ═══
print("=" * 60)
print("  Z3 ARX Solver — 160-bit constraint (seeds + sokey_check)")
print(f"  ARX rounds: {ARX_ROUNDS}")
print(f"  Constraint: 128 bits (seeds) + 32 bits (sokey_check) = 160 bits")
print(f"  Input space: 200 bits (25 bytes)")
print("=" * 60)
print()

def z3_ror64(x, n):
    return LShR(x, n) | (x << (64 - n))

def z3_rol64(x, n):
    return (x << n) | LShR(x, 64 - n)

print("[1/3] Building Z3 model...", flush=True)
t0 = time.time()

# 25 个 8-bit 符号变量
flag = [BitVec(f'f{i}', 8) for i in range(25)]

# 构造 32 字节 buffer (flag + 0x5A padding)
buf = flag + [BitVecVal(0x5A, 8)] * 7

# 组装为 4 × 64-bit (小端)
s = [None] * 4
for i in range(4):
    s[i] = ZeroExt(56, buf[i*8])
    for j in range(1, 8):
        s[i] = s[i] | (ZeroExt(56, buf[i*8+j]) << (j*8))

# 12 轮 ARX
for r in range(ARX_ROUNDS):
    s[0] = (z3_ror64(s[0], 8) + s[1]) ^ BitVecVal(r, 64)
    s[1] = z3_rol64(s[1], 3) ^ s[0]
    s[2] = (z3_ror64(s[2], 8) + s[3]) ^ BitVecVal(r + 4, 64)
    s[3] = z3_rol64(s[3], 3) ^ s[2]
    s[0] = s[0] ^ s[3]
    s[2] = s[2] ^ s[1]

# Squeeze: 提取 material bytes
def extract_material_bytes(state, count):
    result = []
    for i in range(4):
        for j in range(8):
            result.append(Extract(j*8+7, j*8, state[i]))
    return result[:count]

material = []
s_copy = list(s)
for squeeze in range(3):
    material.extend(extract_material_bytes(s_copy, 32))
    s_copy[0] = s_copy[0] + s_copy[2]
    s_copy[1] = s_copy[1] ^ s_copy[3]
    s_copy[2] = z3_rol64(s_copy[2], 17)
    s_copy[3] = z3_ror64(s_copy[3], 11)
material = material[:96]

print(f"    Model build: {time.time()-t0:.1f}s")

# ═══ 添加约束 ═══
print("[2/3] Adding constraints...", flush=True)
solver = Solver()
solver.set("timeout", 43200000)  # 12 hours

# 约束 1: material[80:96] == KNOWN_SEEDS (128 bits)
seeds_bytes = struct.pack('<4I', *KNOWN_SEEDS)
for i in range(16):
    solver.add(material[80+i] == BitVecVal(seeds_bytes[i], 8))

# 约束 2: material[60:64] == target_rk15 (32 bits)
sokey_12_16 = struct.unpack_from('<I', SOKEY, 12)[0]
target_rk15 = EXPECTED_SOKEY_CHECK ^ sokey_12_16
rk15_bytes = struct.pack('<I', target_rk15)
for i in range(4):
    solver.add(material[60+i] == BitVecVal(rk15_bytes[i], 8))

print(f"    Total constraints: 20 equalities (160 bits)")
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
    flag_bytes = bytes([m.eval(flag[i]).as_long() for i in range(25)])
    print(f"  Solution: {flag_bytes.hex()}")
    print(f"  Expected: {FLAG_B_EXPECTED.hex()}")
    print(f"  Match: {flag_bytes == FLAG_B_EXPECTED}")
else:
    print(f"  No solution found")

print("=" * 60)
