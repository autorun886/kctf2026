#!/usr/bin/env python3
"""
test_z3_no_crossmix.py — 测试去掉 cross-mixing 后 12 轮 ARX 的 Z3 求解

去掉 s[0]^=s[3]; s[2]^=s[1] 后：
  - s[0]/s[1] 仅依赖 flag[0:16]（128 bits）
  - s[2]/s[3] 仅依赖 flag[16:25]（72 bits = 9 bytes）

约束 s[2]+s[3] (128 bits) 对 72 bits 输入 → 过约束，Z3 应秒解
约束 s[0]+s[1] 需要额外暴露信息（比如 material[0:16]）

本脚本测试：保留 cross-mixing 但降频率（每 N 轮做一次）
看能否找到既保持安全性又可解的平衡点
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

def get_arx_output(flag_bytes, rounds, cross_mix_interval):
    """cross_mix_interval: 0=never, 1=every round, 2=every 2nd, etc."""
    buf = bytearray(32)
    buf[:25] = flag_bytes; buf[25:] = b'\x5A' * 7
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(rounds):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1<<64)-1); s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1<<64)-1); s[2] ^= (r+4)
        s[3] = rol64(s[3], 3) ^ s[2]
        if cross_mix_interval > 0 and (r % cross_mix_interval == cross_mix_interval - 1):
            s[0] ^= s[3]; s[2] ^= s[1]
    return s

def test_config(rounds, cross_mix_interval, timeout_s=1800):
    """Test a specific ARX config with Z3"""
    ref = get_arx_output(FLAG_B, rounds, cross_mix_interval)
    target_s2 = ref[2]
    target_s3 = ref[3]

    PAD = 0
    for i in range(1, 8): PAD |= (0x5A << (i * 8))

    flag_bv = BitVec('flag', 200)
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
        if cross_mix_interval > 0 and (r % cross_mix_interval == cross_mix_interval - 1):
            s[0] = s[0] ^ s[3]; s[2] = s[2] ^ s[1]

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
        check = get_arx_output(flag_bytes, rounds, cross_mix_interval)
        match = (check[2] == target_s2 and check[3] == target_s3)

    return result, elapsed, flag_bytes, match


print("=" * 60)
print("  ARX Cross-Mix Frequency Sweep")
print("  12 rounds, 128-bit constraint (s[2]+s[3])")
print("  Timeout: 2h each")
print("=" * 60)
print()
print(f"{'Config':<30}{'Result':<10}{'Time':<12}{'Match'}")
print("-" * 60)

configs = [
    (12, 0,  "12R, no cross-mix"),
    (12, 6,  "12R, cross every 6th"),
    (12, 4,  "12R, cross every 4th"),
    (12, 3,  "12R, cross every 3rd"),
    (12, 2,  "12R, cross every 2nd"),
    (12, 1,  "12R, cross every round (original)"),
]

for rounds, interval, label in configs:
    result, elapsed, flag_bytes, match = test_config(rounds, interval, timeout_s=7200)
    time_str = f"{elapsed:.1f}s"
    match_str = "✓" if match else ("-" if not flag_bytes else "✗")
    print(f"{label:<30}{str(result):<10}{time_str:<12}{match_str}")
    if flag_bytes and match:
        print(f"    Solution: {flag_bytes.hex()}")
    if result != sat:
        print(f"    (timeout/unknown)")
