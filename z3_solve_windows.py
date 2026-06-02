#!/usr/bin/env python3
"""
z3_solve_windows.py — KCTF2026 方案 B Z3 约束求解器 (Windows 多线程版)
在 Windows 上运行：python z3_solve_windows.py [--workers N] [--timeout S]
输出：z3_result.txt

依赖：pip install z3-solver
"""
import time, struct, sys, os, argparse, threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed, Future
from multiprocessing import cpu_count, Manager, Event as MPEvent
from threading import Thread, Event, Lock
from queue import Queue
from dataclasses import dataclass
from typing import List, Tuple, Optional

from z3 import *

# ════════════════════════════════════════════════════════════════
# 命令行参数
# ════════════════════════════════════════════════════════════════
parser = argparse.ArgumentParser(description="KCTF2026 Z3 Solver (Windows Multi-threaded)")
parser.add_argument("--workers", type=int, default=min(cpu_count(), 16),
                    help=f"工作线程数 (默认: {min(cpu_count(), 16)})")
parser.add_argument("--timeout", type=int, default=86400,
                    help="Z3 求解超时秒数 (默认: 86400, 即24小时)")
parser.add_argument("--brute-force", action="store_true",
                    help="启用多线程暴力搜索回退")
parser.add_argument("--bf-threads", type=int, default=0,
                    help="暴力搜索线程数 (默认: CPU 核心数)")
args = parser.parse_args()

NUM_WORKERS = args.workers
Z3_TIMEOUT = args.timeout * 1000  # 转毫秒
BF_WORKERS = args.bf_threads if args.bf_threads > 0 else cpu_count()

START = time.time()

# ════════════════════════════════════════════════════════════════
# 已知常量（从 converge.py 输出 / APK 提取）
# ════════════════════════════════════════════════════════════════
SOKEY = bytes.fromhex("0626fbb9ea5656a6b101fe996205b6b0")
ENC_STATE1 = bytes.fromhex("39050544fec6bcf6205b410efa8524eb")
ENC_STATE2 = bytes.fromhex("01d8b786e9d35d01f2979fa4e9876459")
EXPECTED_SOKEY_CHECK = 0xe437295c

IV1 = bytes([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
             0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10])
IV2 = bytes([0xA5,0x5A,0xC3,0x3C,0xF0,0x0F,0x69,0x96,
             0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0])

MDS = [
    [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]],
    [[5,3,4,2],[2,5,3,4],[4,2,5,3],[3,4,2,5]],
    [[7,6,2,3],[3,7,6,2],[2,3,7,6],[6,2,3,7]],
    [[9,14,5,4],[4,9,14,5],[5,4,9,14],[14,5,4,9]],
]
SHIFTS = [[0,1,2,3],[0,1,3,4],[0,2,3,1],[0,3,1,2]]
NL_POWER = [7, 11, 13, 23]

# ════════════════════════════════════════════════════════════════
# GF(2^8) 预计算表（多线程加速）
# ════════════════════════════════════════════════════════════════

def gf_mul_val(a: int, b: int) -> int:
    """GF(2^8) 乘法 (多项式约化: x^8 + x^4 + x^3 + x + 1 = 0x11B)"""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def gf_pow_val(base: int, exp: int) -> int:
    """GF(2^8) 幂运算"""
    r = 1
    while exp:
        if exp & 1:
            r = gf_mul_val(r, base)
        base = gf_mul_val(base, base)
        exp >>= 1
    return r


def _build_pow_table(p: int) -> Tuple[int, List[int]]:
    """为单个幂次构建幂表 (线程安全)"""
    return p, [gf_pow_val(x, p) for x in range(256)]


def _build_mul_chunk(args_tuple: Tuple[range, List[int]]) -> dict:
    """为一个 a 值区间构建乘法表 (线程安全)"""
    a_range, b_values = args_tuple
    result = {}
    for a in a_range:
        for b in b_values:
            result[(a, b)] = gf_mul_val(a, b)
    return result


print(f"{'='*60}")
print(f"  KCTF2026 Scheme B Z3 Solver (Windows Multi-threaded)")
print(f"  CPU cores: {cpu_count()} | Thread workers: {NUM_WORKERS}")
print(f"  Z3 timeout: {args.timeout}s | Brute-force: {'ON' if args.brute_force else 'OFF'}")
print(f"{'='*60}")
print()

# --- 并行构建 GF 幂表 ---
print("[1/4] Building GF power tables (parallel)...", end=" ", flush=True)
_t0 = time.time()
GF_POW_TABLE: dict = {}
with ThreadPoolExecutor(max_workers=min(len(NL_POWER), NUM_WORKERS)) as ex:
    futures = {ex.submit(_build_pow_table, p): p for p in NL_POWER}
    for fut in as_completed(futures):
        p, table = fut.result()
        GF_POW_TABLE[p] = table
print(f"{time.time() - _t0:.2f}s")

# --- 并行构建 GF 乘法表 ---
print("[2/4] Building GF multiplication tables (parallel)...", end=" ", flush=True)
_t0 = time.time()
UNIQUE_B = sorted(set(sum((row for m in MDS for row in m), [])))
chunk_size = max(1, 256 // NUM_WORKERS)
chunks = [(range(i, min(i + chunk_size, 256)), UNIQUE_B) for i in range(0, 256, chunk_size)]

GF_MUL_TABLE: dict = {}
with ThreadPoolExecutor(max_workers=NUM_WORKERS) as ex:
    futures = [ex.submit(_build_mul_chunk, c) for c in chunks]
    for fut in as_completed(futures):
        GF_MUL_TABLE.update(fut.result())
print(f"{time.time() - _t0:.2f}s")


# ════════════════════════════════════════════════════════════════
# CRC32 半字节表
# ════════════════════════════════════════════════════════════════
CRC_TABLE = [0x00000000,0x1DB71064,0x3B6E20C8,0x26D930AC,
             0x76DC4190,0x6B6B51F4,0x4DB26158,0x5005713C,
             0xEDB88320,0xF00F9344,0xD6D6A3E8,0xCB61B38C,
             0x9B64C2B0,0x86D3D2D4,0xA00AE278,0xBDBDF21C]


def crc32_16(data: bytes) -> int:
    """CRC32 半字节查表"""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        crc = ((crc >> 4) ^ CRC_TABLE[crc & 0x0F]) & 0xFFFFFFFF
        crc = ((crc >> 4) ^ CRC_TABLE[crc & 0x0F]) & 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


# ════════════════════════════════════════════════════════════════
# 正向模拟（非 Z3，用于验证）
# ════════════════════════════════════════════════════════════════

def ror64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & ((1 << 64) - 1)


def rol64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)


def expand_key_material(flag_bytes: bytes) -> bytes:
    """16 轮 ARX 展开，输出 96 字节 material"""
    buf = bytearray(32)
    buf[:25] = flag_bytes
    buf[25:] = b'\x5A' * 7
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(16):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1 << 64) - 1)
        s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1 << 64) - 1)
        s[2] ^= (r + 4)
        s[3] = rol64(s[3], 3) ^ s[2]
        s[0] ^= s[3]
        s[2] ^= s[1]
    out = bytearray()
    while len(out) < 96:
        chunk = min(32, 96 - len(out))
        out += struct.pack('<4Q', *s)[:chunk]
        s[0] = (s[0] + s[2]) & ((1 << 64) - 1)
        s[1] ^= s[3]
        s[2] = rol64(s[2], 17)
        s[3] = ror64(s[3], 11)
    return bytes(out)


def key_schedule(flag: bytes, so_key: bytes):
    """密钥编排：从 flag + so_key 生成轮密钥、配置、种子、delta"""
    mat = bytearray(128)
    mat[:96] = expand_key_material(flag)
    for i in range(16):
        mat[96 + i] = mat[i] ^ so_key[i]
    for i in range(16):
        mat[112 + i] = mat[32 + i]
    rk = [struct.unpack_from('<I', mat, i * 4)[0] for i in range(16)]
    cfgs = []
    for i in range(16):
        b = mat[64 + i]
        cfgs.append({
            'ss': (b >> 0) & 3,
            'sp': (b >> 2) & 3,
            'mm': (b >> 4) & 3,
            'nm': (b >> 6) & 3,
        })
    seeds = [struct.unpack_from('<I', mat, 80 + i * 4)[0] for i in range(4)]
    delta = struct.unpack_from('<I', mat, 96)[0]
    check = rk[15] ^ struct.unpack_from('<I', so_key, 12)[0]
    diff = check ^ EXPECTED_SOKEY_CHECK
    poison = (((diff | ((~diff + 1) & 0xFFFFFFFF)) >> 31) & 1) * 0xDEADBEEF
    delta ^= poison
    return rk, cfgs, seeds, delta


def generate_sbox(seed: int) -> List[int]:
    """Fisher-Yates 打乱生成 S-Box"""
    sbox = list(range(256))
    xs = seed & 0xFFFFFFFF
    for i in range(255, 0, -1):
        xs ^= (xs << 13) & 0xFFFFFFFF
        xs ^= (xs >> 17) & 0xFFFFFFFF
        xs ^= (xs << 5) & 0xFFFFFFFF
        sbox[i], sbox[xs % (i + 1)] = sbox[xs % (i + 1)], sbox[i]
    return sbox


def spn_encrypt(state: List[int], rk: List[int], cfgs: List[dict],
                sboxes: List[List[int]], delta: int) -> bytes:
    """SPN 加密 16 轮 (后 8 轮含动态混合)"""
    state = list(state)
    crc_mix = 0
    for rnd in range(16):
        if rnd == 8:
            crc_mix = crc32_16(bytes(state))
        dyn_key = rk[rnd]
        if rnd >= 8:
            dyn_key ^= struct.unpack_from('<I', bytes(state[:4]))[0]
            dyn_key ^= crc_mix
        sel = cfgs[rnd]['ss'] if rnd < 8 else (cfgs[rnd]['ss'] ^ state[0]) & 3
        # S-Box 替换 (查表加速)
        sbox = sboxes[sel]
        state = [sbox[b] for b in state]
        # ShiftRows
        tmp = state[:]
        sp_cfg = cfgs[rnd]['sp']
        for row in range(4):
            s = SHIFTS[sp_cfg][row] & 3
            for col in range(4):
                state[row + 4 * col] = tmp[row + 4 * ((col + s) % 4)]
        # MixColumns
        res = [0] * 16
        m = MDS[cfgs[rnd]['mm']]
        for col in range(4):
            inp = state[col * 4:col * 4 + 4]
            base = col * 4
            for i in range(4):
                mi = m[i]
                v = (GF_MUL_TABLE[(mi[0], inp[0])] ^
                     GF_MUL_TABLE[(mi[1], inp[1])] ^
                     GF_MUL_TABLE[(mi[2], inp[2])] ^
                     GF_MUL_TABLE[(mi[3], inp[3])])
                res[base + i] = v
        state = res
        # Non-linear power + round constant
        power = NL_POWER[cfgs[rnd]['nm'] & 3]
        pow_table = GF_POW_TABLE[power]
        rc = (delta >> ((rnd % 4) * 8)) & 0xFF
        xor_val = rc ^ (rnd & 0xFF)
        state = [pow_table[b ^ xor_val] for b in state]
        # AddRoundKey
        k = struct.pack('<I', dyn_key)
        state = [state[i] ^ k[i % 4] for i in range(16)]
    return bytes(state)


def verify_flag(flag_bytes: bytes, target1: bytes, target2: bytes) -> Tuple[bool, str]:
    """验证一个候选 flag 是否产生正确的加密输出"""
    try:
        rk, cfgs, seeds, delta = key_schedule(flag_bytes, SOKEY)
        # 并行生成 4 个 S-Box
        with ThreadPoolExecutor(max_workers=4) as ex:
            sboxes = list(ex.map(generate_sbox, seeds))
        v1 = spn_encrypt(list(IV1), rk, cfgs, sboxes, delta)
        v2 = spn_encrypt(list(IV2), rk, cfgs, sboxes, delta)
        ok = (v1 == target1) and (v2 == target2)
        detail = f"v1={'OK' if v1 == target1 else 'FAIL'} v2={'OK' if v2 == target2 else 'FAIL'}"
        return ok, detail
    except Exception as e:
        return False, f"error: {e}"


# ════════════════════════════════════════════════════════════════
# Z3 符号执行引擎（在线程中运行）
# ════════════════════════════════════════════════════════════════

def z3_ror64(x, n: int):
    return LShR(x, n) | (x << (64 - n))


def z3_rol64(x, n: int):
    return (x << n) | LShR(x, (64 - n))


def z3_expand(flag_bvs: List):
    """16 轮 ARX 展开为 Z3 符号表达式，返回 96 个 8-bit 符号"""
    buf = [BitVecVal(0x5A, 8)] * 32
    for i in range(25):
        buf[i] = flag_bvs[i]

    s = [None] * 4
    for i in range(4):
        s[i] = ZeroExt(56, buf[i * 8])
        for j in range(1, 8):
            s[i] = s[i] | (ZeroExt(56, buf[i * 8 + j]) << (j * 8))

    for r in range(16):
        s[0] = (z3_ror64(s[0], 8) + s[1]) ^ BitVecVal(r, 64)
        s[1] = z3_rol64(s[1], 3) ^ s[0]
        s[2] = (z3_ror64(s[2], 8) + s[3]) ^ BitVecVal(r + 4, 64)
        s[3] = z3_rol64(s[3], 3) ^ s[2]
        s[0] = s[0] ^ s[3]
        s[2] = s[2] ^ s[1]

    out = []
    for _ in range(3):
        for i in range(4):
            for j in range(8):
                out.append(Extract(j * 8 + 7, j * 8, s[i]))
        s[0] = s[0] + s[2]
        s[1] = s[1] ^ s[3]
        s[2] = z3_rol64(s[2], 17)
        s[3] = z3_ror64(s[3], 11)

    return out[:96]


@dataclass
class Z3Result:
    """Z3 求解结果"""
    status: str          # "sat", "unsat", "unknown", "timeout", "error"
    flag_bytes: Optional[bytes] = None
    solve_time: float = 0.0
    error_msg: str = ""


def run_z3_solver(expected_material: bytes,
                  timeout_ms: int = 3600000) -> Z3Result:
    """
    在独立线程中运行 Z3 求解器。
    约束：expand_key_material(flag) == expected_material
    """
    try:
        flag = [BitVec(f'f{i}', 8) for i in range(25)]
        material_sym = z3_expand(flag)

        solver = Solver()
        solver.set("timeout", timeout_ms)
        # Z3 内部并行 (如果 Z3 编译时支持)
        solver.set("threads", min(4, cpu_count()))

        for i in range(96):
            solver.add(material_sym[i] == BitVecVal(expected_material[i], 8))

        t1 = time.time()
        result = solver.check()
        elapsed = time.time() - t1

        if result == sat:
            m = solver.model()
            flag_bytes = bytes([m.eval(flag[i]).as_long() for i in range(25)])
            return Z3Result(status="sat", flag_bytes=flag_bytes, solve_time=elapsed)
        elif result == unsat:
            return Z3Result(status="unsat", solve_time=elapsed)
        else:
            return Z3Result(status="unknown", solve_time=elapsed)
    except Exception as e:
        return Z3Result(status="error", error_msg=str(e))


# ════════════════════════════════════════════════════════════════
# 多线程暴力搜索回退引擎
# ════════════════════════════════════════════════════════════════

# 搜索空间：flag[20:24] 的 4 字节（32-bit 暴力可行）
# 假设前 20 字节已知或从 partial 解推出
BF_FLAG_PREFIX = bytes([
    0x7A, 0xE3, 0x1B, 0x94, 0xD2, 0x56, 0xF8, 0x0C,
    0x41, 0xB7, 0x29, 0x8E, 0x63, 0xA5, 0xDF, 0x10,
    0x4B, 0xC8, 0x72, 0x3D,  # 前 20 字节
])

BF_FLAG_SUFFIX = bytes([0xAD])  # 最后 1 字节

FOUND_FLAG = None
FOUND_LOCK = None  # threading.Lock (在主线程初始化)


def _bf_worker(worker_id: int, start_val: int, end_val: int,
               target1: bytes, target2: bytes,
               found_event, result_queue) -> None:
    """
    暴力搜索工作线程。
    搜索 flag[20:24] 的 4 字节组合。
    """
    global FOUND_FLAG
    prefix = BF_FLAG_PREFIX
    suffix = BF_FLAG_SUFFIX

    for val in range(start_val, end_val):
        if found_event.is_set():
            return

        # 构造候选 flag
        candidate = prefix + struct.pack('>I', val) + suffix

        ok, _detail = verify_flag(candidate, target1, target2)
        if ok:
            with FOUND_LOCK:
                if FOUND_FLAG is None:
                    FOUND_FLAG = candidate
            found_event.set()
            result_queue.put(("found", candidate, worker_id))
            return

        # 每 100000 次检查输出进度
        if (val - start_val) % 100000 == 0 and val != start_val:
            progress = (val - start_val) / (end_val - start_val) * 100
            result_queue.put(("progress", worker_id, progress))

    result_queue.put(("done", worker_id, None))


def brute_force_search(target1: bytes, target2: bytes,
                       num_threads: int = 8) -> Optional[bytes]:
    """
    多线程暴力搜索 flag[20:24] 的 4 字节。
    返回找到的 flag，或 None。
    """
    global FOUND_FLAG, FOUND_LOCK
    FOUND_LOCK = Lock()
    FOUND_FLAG = None

    total_space = 0x100000000  # 2^32
    chunk_size = total_space // num_threads
    found_event = Event()
    result_queue = Queue()

    print(f"\n[*] Starting brute-force: {num_threads} threads, "
          f"search space 2^32 (~4.3 billion)")
    print(f"[*] Each thread covers ~{chunk_size:,} values")
    _bf_start = time.time()

    threads = []
    for i in range(num_threads):
        start_val = i * chunk_size
        end_val = total_space if i == num_threads - 1 else (i + 1) * chunk_size
        t = Thread(target=_bf_worker, args=(
            i, start_val, end_val, target1, target2, found_event, result_queue
        ), daemon=True)
        threads.append(t)
        t.start()

    # 监控进度
    worker_progress = {i: 0.0 for i in range(num_threads)}
    active_workers = num_threads

    while active_workers > 0 and not found_event.is_set():
        try:
            msg = result_queue.get(timeout=5)
            if msg[0] == "found":
                print(f"\n[!] Thread-{msg[2]} FOUND the flag!")
                return msg[1]
            elif msg[0] == "progress":
                worker_progress[msg[1]] = msg[2]
                avg = sum(worker_progress.values()) / num_threads
                elapsed = time.time() - _bf_start
                if avg > 0:
                    eta = elapsed / (avg / 100) - elapsed
                    print(f"\r    Progress: {avg:.1f}% | Elapsed: {elapsed:.0f}s | "
                          f"ETA: {eta:.0f}s   ", end="", flush=True)
            elif msg[0] == "done":
                active_workers -= 1
        except Exception:
            # queue timeout, check found_event
            pass

    elapsed = time.time() - _bf_start
    print(f"\n[*] Brute-force completed in {elapsed:.1f}s")

    if FOUND_FLAG:
        return FOUND_FLAG
    return None


# ════════════════════════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════════════════════════

def main():
    print("[3/4] Initializing targets and expected material...")
    target1 = bytes(ENC_STATE1[i] ^ SOKEY[i] for i in range(16))
    target2 = bytes(ENC_STATE2[i] ^ SOKEY[i] for i in range(16))
    print(f"      target1 = {target1.hex()}")
    print(f"      target2 = {target2.hex()}")

    # 已知 Flag (用于验证和构造 expected_material)
    FLAG_B = bytes([0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
                    0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
                    0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])

    expected_material = expand_key_material(FLAG_B)
    print(f"      expected_material[0:16] = {expected_material[:16].hex()}")

    # --- 并行正向验证 ---
    print("[4/4] Running forward verification (parallel)...", end=" ", flush=True)
    _t0 = time.time()
    with ThreadPoolExecutor(max_workers=2) as ex:
        fut1 = ex.submit(verify_flag, FLAG_B, target1, target2)
        fut2 = ex.submit(verify_flag, FLAG_B, target1, target2)  # redundant but tests parallelism
        ok1, detail1 = fut1.result()
    print(f"{time.time() - _t0:.2f}s")
    print(f"      Forward verification: {'PASS' if ok1 else 'FAIL'} ({detail1})")
    print()

    # ═══ Z3 求解（主线程 + 超时监控线程）═══
    print(f"{'='*60}")
    print(f"  Phase 1: Z3 Constraint Solving")
    print(f"  Timeout: {args.timeout}s | Z3 threads: {min(4, cpu_count())}")
    print(f"{'='*60}")

    z3_result = [None]  # 用列表包装以在线程间共享
    z3_done = Event()

    def _z3_thread():
        z3_result[0] = run_z3_solver(expected_material, Z3_TIMEOUT)
        z3_done.set()

    z3_thread = Thread(target=_z3_thread, daemon=True)
    z3_thread.start()

    # 等待 Z3 完成（带进度指示）
    dots = 0
    while not z3_done.is_set():
        z3_thread.join(timeout=10)
        if not z3_done.is_set():
            dots = (dots + 1) % 4
            elapsed = time.time() - START
            print(f"\r    Solving{'.' * (dots + 1):<4} [{elapsed:.0f}s elapsed]", end="", flush=True)

    result = z3_result[0]
    print()  # newline after progress

    # ═══ 收集结果 ═══
    output = []
    output.append(f"KCTF2026 Z3 Solver Result (Windows Multi-threaded)")
    output.append(f"{'='*60}")
    output.append(f"Solver: Z3 {z3.get_version_string()}")
    output.append(f"Platform: Windows | Workers: {NUM_WORKERS}")
    output.append(f"Strategy: ARX inversion (material constraint)")
    output.append(f"ARX rounds: 16 | SPN rounds: 16 (8 static + 8 dynamic)")
    output.append(f"CRC32 mix: yes (at round 8) | Dual IV: yes")
    output.append(f"")
    output.append(f"soKey: {SOKEY.hex()}")
    output.append(f"EXPECTED_SOKEY_CHECK: 0x{EXPECTED_SOKEY_CHECK:08x}")
    output.append(f"target1: {target1.hex()}")
    output.append(f"target2: {target2.hex()}")
    output.append(f"")
    output.append(f"Build time: {time.time() - START - result.solve_time:.1f}s")
    output.append(f"Solve time: {result.solve_time:.1f}s")
    output.append(f"Total time: {time.time() - START:.1f}s")
    output.append(f"Z3 Result: {result.status}")
    output.append(f"")

    final_flag = None

    if result.status == "sat" and result.flag_bytes:
        final_flag = result.flag_bytes
        output.append(f"FLAG_B (hex): {result.flag_bytes.hex()}")
        output.append(f"FLAG_B match expected: {result.flag_bytes == FLAG_B}")

        # 完整验证 (并行)
        with ThreadPoolExecutor(max_workers=2) as ex:
            fut_v = ex.submit(verify_flag, result.flag_bytes, target1, target2)
            ok_v, detail_v = fut_v.result()
        output.append(f"SPN verification: {'PASS' if ok_v else 'FAIL'} ({detail_v})")

    elif args.brute_force:
        # ═══ 回退：多线程暴力搜索 ═══
        print(f"\n{'='*60}")
        print(f"  Phase 2: Multi-threaded Brute-force Fallback")
        print(f"  Threads: {BF_WORKERS} | Space: flag[20:24] (32-bit)")
        print(f"{'='*60}")

        bf_result = brute_force_search(target1, target2, BF_WORKERS)
        if bf_result:
            final_flag = bf_result
            output.append(f"FLAG_B (brute-force, hex): {bf_result.hex()}")
            output.append(f"FLAG_B match expected: {bf_result == FLAG_B}")
        else:
            output.append(f"Brute-force: no match found in search space")
    else:
        output.append(f"No solution found (Z3 timeout/unknown)")
        output.append(f"Tip: re-run with --brute-force to enable parallel brute-force fallback")

    output.append(f"")
    output.append(f"{'='*60}")

    result_text = "\n".join(output)
    print(f"\n{result_text}")

    with open("z3_result.txt", "w", encoding="utf-8") as f:
        f.write(result_text)

    print(f"\n[*] Result written to z3_result.txt")

    return final_flag


if __name__ == "__main__":
    # Windows 多进程兼容保护
    # multiprocessing.freeze_support()  # 如果使用 ProcessPoolExecutor 则需要
    main()
