#!/usr/bin/env python3
"""
test_z3_strategies.py — 多种 Z3 求解策略对比测试

在 12 轮 ARX（原版 cross-mix every round）+ 128-bit 约束(s[2],s[3])下
测试不同求解策略，看哪种能突破：

策略 1: 默认 Solver（已知 30min 超时）
策略 2: bit-blast + SAT（跳过高层推理，直接布尔化）
策略 3: 分段约束（先约束 s[3] 的低 32 bit，逐步加强）
策略 4: 增量求解（incremental，逐字节约束）
策略 5: 分治：先猜 flag[16:25]（72 bits），缩小搜索空间
策略 6: STP/Boolector 风格：纯 bit-blast + CaDiCaL
策略 7: 并行多策略竞赛
"""
import struct, time, sys
from z3 import *

FLAG_B = bytes([
    0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
    0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
    0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])

def ror64(x, n): return ((x >> n) | (x << (64 - n))) & ((1 << 64) - 1)
def rol64(x, n): return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)

def z3_ror64(x, n): return LShR(x, n) | (x << (64 - n))
def z3_rol64(x, n): return (x << n) | LShR(x, 64 - n)

def get_arx_output(flag_bytes, rounds=12):
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

ref = get_arx_output(FLAG_B)
TARGET_S2, TARGET_S3 = ref[2], ref[3]

TIMEOUT = 3600000  # 1h per strategy

def build_arx_model():
    """构建 ARX 符号模型，返回 (flag_bv, s_final)"""
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
    return flag_bv, s


def strategy_tactic_bblast(timeout_ms):
    """策略 2: simplify → bit-blast → SAT"""
    print("  [Strategy: bit-blast pipeline]")
    flag_bv, s = build_arx_model()

    t = Then(
        With('simplify', flat=True, hi_div0=True),
        'solve-eqs',
        'bit-blast',
        'sat'
    )
    solver = t.solver()
    solver.set("timeout", timeout_ms)
    solver.add(s[2] == BitVecVal(TARGET_S2, 64))
    solver.add(s[3] == BitVecVal(TARGET_S3, 64))

    t1 = time.time()
    result = solver.check()
    return result, time.time() - t1, solver, flag_bv


def strategy_incremental(timeout_ms):
    """策略 4: 增量求解 — 逐 8-bit 加约束，利用 learned clauses"""
    print("  [Strategy: incremental byte-by-byte]")
    flag_bv, s = build_arx_model()

    solver = Solver()
    solver.set("timeout", timeout_ms)

    # 先加 s[3] 的约束（逐字节）
    for byte_idx in range(8):
        lo = byte_idx * 8
        hi = lo + 7
        target_byte = (TARGET_S3 >> lo) & 0xFF
        solver.add(Extract(hi, lo, s[3]) == BitVecVal(target_byte, 8))

    # 检查 s[3] 约束是否有解
    t1 = time.time()
    r1 = solver.check()
    t_s3 = time.time() - t1
    print(f"    s[3] only: {r1} ({t_s3:.1f}s)")

    if r1 != sat:
        return r1, t_s3, solver, flag_bv

    # 再逐字节加 s[2]
    for byte_idx in range(8):
        lo = byte_idx * 8
        hi = lo + 7
        target_byte = (TARGET_S2 >> lo) & 0xFF
        solver.add(Extract(hi, lo, s[2]) == BitVecVal(target_byte, 8))

        t_check = time.time()
        r = solver.check()
        elapsed = time.time() - t_check
        print(f"    s[2] byte {byte_idx}: {r} ({elapsed:.1f}s)")

        if r != sat:
            return r, time.time() - t1, solver, flag_bv

    return sat, time.time() - t1, solver, flag_bv


def strategy_split_halves(timeout_ms):
    """策略 5: 分治 — 先固定 flag[0:16] 为已知值（模拟部分信息已知），
    只求解 flag[16:25]。如果这都超时说明问题在 ARX 结构本身。"""
    print("  [Strategy: fix flag[0:16], solve flag[16:25] only (72 bits)]")

    # 25 个独立 8-bit 变量
    flag_vars = [BitVec(f'f{i}', 8) for i in range(25)]
    buf = flag_vars + [BitVecVal(0x5A, 8)] * 7

    # 组装 64-bit 状态
    def bytes_to_bv64(blist):
        r = ZeroExt(56, blist[0])
        for j in range(1, 8):
            r = r | (ZeroExt(56, blist[j]) << (j * 8))
        return r

    s = [bytes_to_bv64(buf[i*8:(i+1)*8]) for i in range(4)]

    for r in range(12):
        s[0] = (z3_ror64(s[0], 8) + s[1]) ^ BitVecVal(r, 64)
        s[1] = z3_rol64(s[1], 3) ^ s[0]
        s[2] = (z3_ror64(s[2], 8) + s[3]) ^ BitVecVal(r + 4, 64)
        s[3] = z3_rol64(s[3], 3) ^ s[2]
        s[0] = s[0] ^ s[3]
        s[2] = s[2] ^ s[1]

    solver = Solver()
    solver.set("timeout", timeout_ms)

    # 固定 flag[0:16] 为已知值（选手通过其他约束已确定这些字节）
    for i in range(16):
        solver.add(flag_vars[i] == BitVecVal(FLAG_B[i], 8))

    # 约束输出
    solver.add(s[2] == BitVecVal(TARGET_S2, 64))
    solver.add(s[3] == BitVecVal(TARGET_S3, 64))

    t1 = time.time()
    result = solver.check()
    elapsed = time.time() - t1

    return result, elapsed, solver, None


def strategy_qfbv_smt(timeout_ms):
    """策略 6: QF_BV 专用 tactic (Z3 内置优化路径)"""
    print("  [Strategy: qfbv tactic]")
    flag_bv, s = build_arx_model()

    t = Then('simplify', 'qfbv')
    solver = t.solver()
    solver.set("timeout", timeout_ms)
    solver.add(s[2] == BitVecVal(TARGET_S2, 64))
    solver.add(s[3] == BitVecVal(TARGET_S3, 64))

    t1 = time.time()
    result = solver.check()
    return result, time.time() - t1, solver, flag_bv


def strategy_propagate_then_solve(timeout_ms):
    """策略 7: propagate-values + solve-eqs 预简化后再 bit-blast"""
    print("  [Strategy: propagate → solve-eqs → bit-blast]")
    flag_bv, s = build_arx_model()

    t = Then(
        With('simplify', flat=True),
        'propagate-values',
        'solve-eqs',
        'elim-uncnstr',
        'bit-blast',
        'sat'
    )
    solver = t.solver()
    solver.set("timeout", timeout_ms)
    solver.add(s[2] == BitVecVal(TARGET_S2, 64))
    solver.add(s[3] == BitVecVal(TARGET_S3, 64))

    t1 = time.time()
    result = solver.check()
    return result, time.time() - t1, solver, flag_bv


# ═══ 执行 ═══
print("=" * 60)
print("  Z3 Strategy Comparison — 12R ARX, 128-bit constraint")
print(f"  Timeout: {TIMEOUT//1000}s per strategy")
print("=" * 60)
print()

strategies = [
    ("bit-blast pipeline",     strategy_tactic_bblast),
    ("incremental",            strategy_incremental),
    ("fix flag[0:16] (72-bit)",strategy_split_halves),
    ("qfbv tactic",            strategy_qfbv_smt),
    ("propagate+bblast",       strategy_propagate_then_solve),
]

results_summary = []

for name, fn in strategies:
    print(f"\n{'─'*50}")
    print(f"  Testing: {name}")
    print(f"{'─'*50}")
    result, elapsed, solver, flag_bv = fn(TIMEOUT)
    status = str(result)
    print(f"  → {status} in {elapsed:.1f}s ({elapsed/60:.1f} min)")

    if result == sat:
        if flag_bv is not None:
            m = solver.model()
            val = m.eval(flag_bv).as_long()
            fb = val.to_bytes(25, 'little')
        else:
            # 从独立变量提取
            m = solver.model()
            fb = bytes([m.eval(BitVec(f'f{i}', 8)).as_long() for i in range(25)])
        check = get_arx_output(fb)
        ok = check[2] == TARGET_S2 and check[3] == TARGET_S3
        print(f"  → Solution: {fb.hex()}")
        print(f"  → Verify: {'✓' if ok else '✗'}")
        print(f"  → Match expected: {fb == FLAG_B}")
        results_summary.append((name, status, elapsed, True))
        # 一旦找到有效策略，后面的可以跳过
    else:
        results_summary.append((name, status, elapsed, False))

print(f"\n\n{'='*60}")
print("  Summary")
print(f"{'='*60}")
print(f"{'Strategy':<30}{'Result':<10}{'Time':<12}")
print("-" * 52)
for name, status, elapsed, solved in results_summary:
    print(f"{name:<30}{status:<10}{elapsed:.1f}s")
