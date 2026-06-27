#!/usr/bin/env python3
"""
test_z3_24bytes.py — 测试 24 bytes (192 bits) 约束的 Z3 求解时间（不限时）
"""
import struct, time
from z3 import *

FLAG_B = bytes([
    0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
    0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
    0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])

def ror64(x, n): return ((x >> n) | (x << (64 - n))) & ((1 << 64) - 1)
def rol64(x, n): return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)

def z3_ror64(x, n): return LShR(x, n) | (x << (64 - n))
def z3_rol64(x, n): return (x << n) | LShR(x, 64 - n)

def expand_key_material(flag_bytes):
    buf = bytearray(32)
    buf[:25] = flag_bytes; buf[25:] = b'\x5A' * 7
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(12):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1<<64)-1); s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1<<64)-1); s[2] ^= (r+4)
        s[3] = rol64(s[3], 3) ^ s[2]
        s[0] ^= s[3]; s[2] ^= s[1]
    out = bytearray()
    while len(out) < 96:
        chunk = min(32, 96 - len(out))
        out += struct.pack('<4Q', *s)[:chunk]
        s[0] = (s[0] + s[2]) & ((1<<64)-1); s[1] ^= s[3]
        s[2] = rol64(s[2], 17); s[3] = ror64(s[3], 11)
    return bytes(out)

EXPECTED_MATERIAL = expand_key_material(FLAG_B)

print("=" * 60)
print("  Z3 Test: 24 bytes (192 bits) constraint, NO timeout")
print("  material[0:24] == known")
print("=" * 60)
print()
print(f"  Expected flag: {FLAG_B.hex()}")
print(f"  material[0:24]: {EXPECTED_MATERIAL[:24].hex()}")
print()

# 建模
flag_bv = BitVec('flag', 200)
PAD = 0
for i in range(1, 8): PAD |= (0x5A << (i * 8))

s0 = Extract(63, 0, flag_bv)
s1 = Extract(127, 64, flag_bv)
s2 = Extract(191, 128, flag_bv)
s3 = ZeroExt(56, Extract(199, 192, flag_bv)) | BitVecVal(PAD, 64)
s = [s0, s1, s2, s3]

for r in range(12):
    s[0] = (z3_ror64(s[0], 8) + s[1]) ^ BitVecVal(r, 64)
    s[1] = z3_rol64(s[1], 3) ^ s[0]
    s[2] = (z3_ror64(s[2], 8) + s[3]) ^ BitVecVal(r + 4, 64)
    s[3] = z3_rol64(s[3], 3) ^ s[2]
    s[0] = s[0] ^ s[3]
    s[2] = s[2] ^ s[1]

# Squeeze 提取 material[0:32]（直接是 ARX 输出 s[0..3]）
material_syms = []
for i in range(4):
    for j in range(8):
        material_syms.append(Extract(j*8+7, j*8, s[i]))

# 约束 material[0:24]
solver = Solver()
# 不设 timeout
for i in range(24):
    solver.add(material_syms[i] == BitVecVal(EXPECTED_MATERIAL[i], 8))

print(f"[*] Constraints: 24 bytes (192 bits) on material[0:24]")
print(f"[*] Solving (no timeout)...")
print(f"[*] Start: {time.strftime('%H:%M:%S')}")

t1 = time.time()
result = solver.check()
elapsed = time.time() - t1

print()
print("=" * 60)
print(f"  Result: {result}")
print(f"  Time: {elapsed:.1f}s ({elapsed/60:.1f} min, {elapsed/3600:.2f} hours)")
print(f"  End: {time.strftime('%H:%M:%S')}")

if result == sat:
    m = solver.model()
    val = m.eval(flag_bv).as_long()
    flag_bytes = val.to_bytes(25, 'little')
    print(f"  Solution: {flag_bytes.hex()}")
    print(f"  Expected: {FLAG_B.hex()}")
    print(f"  Match: {flag_bytes == FLAG_B}")
else:
    print(f"  No solution")

print("=" * 60)
