#!/usr/bin/env python3
"""
test_z3_material_sweep.py — 寻找 Z3 可解的最少 material 暴露量

已知：768 bits (96 bytes) → 8.5 min ✓
已知：128 bits (16 bytes) → 超时 ✗

测试：逐步增加约束量，找到 Z3 可解的阈值
约束选在 material[0:N]（第一轮 squeeze 直出，表达式最浅）
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


def test_nbytes(n_bytes, timeout_s=1800):
    """约束 material[0:n_bytes]，测试 Z3 求解时间"""
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

    # Squeeze 提取 material
    material_syms = []
    sq = list(s)
    for squeeze_round in range(3):
        for i in range(4):
            for j in range(8):
                material_syms.append(Extract(j*8+7, j*8, sq[i]))
        sq[0] = sq[0] + sq[2]
        sq[1] = sq[1] ^ sq[3]
        sq[2] = z3_rol64(sq[2], 17)
        sq[3] = z3_ror64(sq[3], 11)

    # 约束 material[0:n_bytes]
    solver = Solver()
    solver.set("timeout", timeout_s * 1000)
    for i in range(n_bytes):
        solver.add(material_syms[i] == BitVecVal(EXPECTED_MATERIAL[i], 8))

    t1 = time.time()
    result = solver.check()
    elapsed = time.time() - t1

    flag_bytes = None
    if result == sat:
        m = solver.model()
        val = m.eval(flag_bv).as_long()
        flag_bytes = val.to_bytes(25, 'little')

    return result, elapsed, flag_bytes


print("=" * 60)
print("  Material Byte Sweep: find minimum for Z3 solvability")
print("  12 rounds ARX + squeeze, timeout 30min each")
print("  Constraint: material[0:N] == known")
print("=" * 60)
print()
print(f"{'Bytes':<8}{'Bits':<8}{'Result':<10}{'Time':<12}{'Match'}")
print("-" * 50)

# 从多到少测试，找到阈值
for n in [96, 64, 48, 40, 32, 24, 20, 16]:
    result, elapsed, flag_bytes = test_nbytes(n, timeout_s=1800)
    bits = n * 8
    match = "✓" if (flag_bytes == FLAG_B) else ("?" if flag_bytes else "-")
    print(f"{n:<8}{bits:<8}{str(result):<10}{elapsed:.1f}s{'':<4}{match}")
    if flag_bytes:
        print(f"    → {flag_bytes.hex()}")

    # 如果超时了，更大的 N 肯定也超时（表达式更深的情况除外）
    # 但这里 material[0:N] 都在 squeeze 0，表达式深度一样
    # 所以如果某个 N 解出，比它大的也应该解出（约束更多=搜索空间更小）
    # 从大到小试：一旦超时就停
    if result != sat:
        print(f"    → {n} bytes 超时，停止")
        break
