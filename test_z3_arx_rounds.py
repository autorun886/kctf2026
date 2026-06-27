#!/usr/bin/env python3
"""
test_z3_arx_rounds.py — 测试不同 ARX 轮数下 Z3 的求解时间
用 128-bit 约束（s[2], s[3] 已知），逐步降低轮数找到可解阈值

每个轮数跑 10 分钟，如果解出就继续下一个更高轮数
"""
import struct, time
from z3 import *

def ror64(x, n): return ((x >> n) | (x << (64 - n))) & ((1 << 64) - 1)
def rol64(x, n): return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)

FLAG_B = bytes([
    0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
    0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
    0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])

def get_arx_output(flag_bytes, rounds):
    buf = bytearray(32)
    buf[:25] = flag_bytes; buf[25:] = b'\x5A' * 7
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(rounds):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1<<64)-1); s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1<<64)-1); s[2] ^= (r+4)
        s[3] = rol64(s[3], 3) ^ s[2]
        s[0] ^= s[3]; s[2] ^= s[1]
    return s

def z3_ror64(x, n):
    return LShR(x, n) | (x << (64 - n))
def z3_rol64(x, n):
    return (x << n) | LShR(x, 64 - n)

def test_rounds(rounds, timeout_s=600):
    """测试指定轮数的 ARX 是否可解"""
    # 计算该轮数下的正确 s[2], s[3]
    ref = get_arx_output(FLAG_B, rounds)
    target_s2 = ref[2]
    target_s3 = ref[3]

    # Z3 建模
    flag_bv = BitVec('flag', 200)
    PAD = 0
    for i in range(1, 8):
        PAD |= (0x5A << (i * 8))

    s0 = Extract(63, 0, flag_bv)
    s1 = Extract(127, 64, flag_bv)
    s2 = Extract(191, 128, flag_bv)
    s3 = ZeroExt(56, Extract(199, 192, flag_bv)) | BitVecVal(PAD, 64)
    s = [s0, s1, s2, s3]

    for r in range(rounds):
        s[0] = (z3_ror64(s[0], 8) + s[1]) ^ BitVecVal(r, 64)
        s[1] = z3_rol64(s[1], 3) ^ s[0]
        s[2] = (z3_ror64(s[2], 8) + s[3]) ^ BitVecVal(r + 4, 64)
        s[3] = z3_rol64(s[3], 3) ^ s[2]
        s[0] = s[0] ^ s[3]
        s[2] = s[2] ^ s[1]

    solver = Solver()
    solver.set("timeout", timeout_s * 1000)
    solver.add(s[2] == BitVecVal(target_s2, 64))
    solver.add(s[3] == BitVecVal(target_s3, 64))

    t1 = time.time()
    result = solver.check()
    elapsed = time.time() - t1

    flag_bytes = None
    match = False
    if result == sat:
        m = solver.model()
        flag_val = m.eval(flag_bv).as_long()
        flag_bytes = flag_val.to_bytes(25, 'little')
        # 验证
        check = get_arx_output(flag_bytes, rounds)
        match = (check[2] == target_s2 and check[3] == target_s3)

    return result, elapsed, flag_bytes, match


print("=" * 60)
print("  ARX Round Sweep: finding solvable threshold")
print("  Constraint: s[2] + s[3] = 128 bits")
print("  Input: 200 bits (25 bytes)")
print("  Timeout per test: 30 min")
print("=" * 60)
print()
print(f"{'Rounds':<8}{'Result':<12}{'Time':<12}{'Match':<8}")
print("-" * 40)

for rounds in [4, 6, 8, 10, 12]:
    result, elapsed, flag_bytes, match = test_rounds(rounds, timeout_s=1800)
    status = str(result)
    time_str = f"{elapsed:.1f}s"
    match_str = "✓" if match else ("-" if not flag_bytes else "✗")
    print(f"{rounds:<8}{status:<12}{time_str:<12}{match_str:<8}")

    if result != sat:
        print(f"\n  → {rounds} rounds: Z3 cannot solve in 10 min")
        print(f"  → Maximum solvable rounds: {rounds - 2}")
        break
    else:
        print(f"    Solution: {flag_bytes.hex()}")
