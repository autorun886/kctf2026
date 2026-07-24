#!/usr/bin/env python3
"""
KCTF2026 read-only keygen.

This script does not patch, rebuild, or modify the APK.  It only reads the APK,
recovers the two 25-byte halves, and prints the final 50-byte hex input.

Default behavior:
  - derive soKey from the APK's stable guard section;
  - solve flagB with the recovered ARX constraints using Z3;
  - derive flagA from the recovered BB offsets used by the current release;
  - interleave flagA and flagB.

Use --use-known-flagb for a quick run that skips the several-minute Z3 solve.
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent
DEFAULT_APK = ROOT / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk"

GUARD_BYTES = bytes.fromhex(
    "e0cc9cd22041adf2a0d0d5f2e06cf7f2"
    "416e9ed2c18da7f241a7def2e1a9f4f2"
    "020001ca4234c293429416914374c0ca"
    "6300018b6344c393600002cac0035fd6"
    "1f2003d51f2003d51f2003d51f2003d5"
    "1f2003d51f2003d51f2003d51f2003d5"
)

# Current release BB offsets.  These are the values used by flag_generate.py.
BB_OFFSETS = {
    "BB0_BRANCH_OFF": 0x3450,
    "BB1_OFF": 0x3458,
    "BB4_BRANCH_OFF": 0x37B8,
    "DEAD_BLOCK_OFF": 0x37BC,
    "BB5_OFF": 0x37CC,
    "BB6_ADR_OFF": 0x3948,
    "BB7_ENTRY_OFF": 0x3950,
}

# Scheme-B constraints recovered from the oracle and key schedule.
KNOWN_SEEDS = (0x24BE739F, 0x966CDDA1, 0xBB2307B9, 0xC9FDCDA7)
KNOWN_MATERIAL_0_16 = bytes.fromhex("c1914230477ab65807b943e4d69eb09e")

# This is material[60:64], not round_keys[15].  round_keys[15] also mixes the
# IPC share in key_schedule().
KNOWN_MATERIAL_60_64 = struct.pack("<I", 0xEE6D3DD9)

# Known recovered value for quick mode and for solver cross-checking.
KNOWN_FLAG_B = bytes.fromhex("7ae31b94d256f80c41b7298e63a5df104bc8723d960fe458ad")

IV1 = bytes(
    [
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF,
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
    ]
)

IV2 = bytes(
    [
        0xA5,
        0x5A,
        0xC3,
        0x3C,
        0xF0,
        0x0F,
        0x69,
        0x96,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9A,
        0xBC,
        0xDE,
        0xF0,
    ]
)

MDS = [
    [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]],
    [[5, 3, 4, 2], [2, 5, 3, 4], [4, 2, 5, 3], [3, 4, 2, 5]],
    [[7, 6, 2, 3], [3, 7, 6, 2], [2, 3, 7, 6], [6, 2, 3, 7]],
    [[9, 14, 5, 4], [4, 9, 14, 5], [5, 4, 9, 14], [14, 5, 4, 9]],
]
SHIFTS = [[0, 1, 2, 3], [0, 1, 3, 4], [0, 2, 3, 1], [0, 3, 1, 2]]
NL_POWER = [7, 11, 13, 23]


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def read_apk_so(apk_path: Path) -> bytes:
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read("lib/arm64-v8a/libkctf.so")


def parse_elf_sections(elf: bytes) -> dict[str, tuple[int, int]]:
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        raise ValueError("expected a little-endian ELF64 shared object")

    e_shoff = u64(elf, 40)
    e_shentsize = u16(elf, 58)
    e_shnum = u16(elf, 60)
    e_shstrndx = u16(elf, 62)
    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("ELF has no section table")

    shstr = elf[e_shoff + e_shstrndx * e_shentsize : e_shoff + (e_shstrndx + 1) * e_shentsize]
    strtab_off = u64(shstr, 24)
    strtab_size = u64(shstr, 32)
    strtab = elf[strtab_off : strtab_off + strtab_size]

    sections: dict[str, tuple[int, int]] = {}
    for i in range(e_shnum):
        sh = elf[e_shoff + i * e_shentsize : e_shoff + (i + 1) * e_shentsize]
        name_idx = struct.unpack_from("<I", sh, 0)[0]
        end = strtab.find(b"\x00", name_idx)
        if end < 0:
            continue
        name = strtab[name_idx:end].decode("ascii", errors="replace")
        off = u64(sh, 24)
        size = u64(sh, 32)
        sections[name] = (off, size)
    return sections


def derive_sokey(so: bytes) -> tuple[bytes, int, str]:
    sections = parse_elf_sections(so)
    if ".kctfguard" in sections:
        off, size = sections[".kctfguard"]
        guard = so[off : off + size]
        source = ".kctfguard"
    else:
        off, size = sections[".text"]
        text = so[off : off + size]
        pos = text.find(GUARD_BYTES)
        if pos < 0:
            raise RuntimeError("guard bytes not found in .text")
        guard = text[pos : pos + len(GUARD_BYTES)]
        source = ".text guard bytes"

    crc = zlib.crc32(guard) & 0xFFFFFFFF
    expand = (
        0xA3F1B28C7D4E5F60,
        0x9C8B7A6D5E4F3021,
        0x1F2E3D4C5B6A7980,
        0xD0E1F2038495A6B7,
    )
    key = bytearray(16)
    for i, e in enumerate(expand):
        m = ((crc ^ e) * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & ((1 << 64) - 1)
        key[i * 4 : i * 4 + 4] = bytes(
            ((m >> 24) & 0xFF, (m >> 16) & 0xFF, (m >> 8) & 0xFF, m & 0xFF)
        )
    return bytes(key), crc, source


def build_flag_a(so_key: bytes) -> bytes:
    out = bytearray(25)

    imm26 = (BB_OFFSETS["BB1_OFF"] - BB_OFFSETS["BB0_BRANCH_OFF"]) // 4
    struct.pack_into("<I", out, 0, imm26 & 0x03FFFFFF)
    out[4] = 0x01

    b4 = ((BB_OFFSETS["BB5_OFF"] - BB_OFFSETS["DEAD_BLOCK_OFF"]) // 4) ^ (
        (BB_OFFSETS["DEAD_BLOCK_OFF"] - BB_OFFSETS["BB4_BRANCH_OFF"]) // 4
    )
    struct.pack_into("<I", out, 5, b4 ^ u32(so_key, 8))

    imm21 = BB_OFFSETS["BB7_ENTRY_OFF"] - BB_OFFSETS["BB6_ADR_OFF"]
    adr_bits = ((imm21 & 0x3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5)
    struct.pack_into("<I", out, 9, adr_bits ^ u32(so_key, 0))

    struct.pack_into("<I", out, 13, 0x9E3779B9)
    struct.pack_into("<I", out, 17, 0xDEADC0DE)
    out[21:25] = bytes((0x07, 0x42, 0x13, 0x37))
    return bytes(out)


def ror64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & ((1 << 64) - 1)


def rol64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)


def expand_key_material(flag_bytes: bytes, out_len: int = 96) -> bytes:
    if len(flag_bytes) != 25:
        raise ValueError(f"flagB must be 25 bytes, got {len(flag_bytes)}")

    buf = bytearray(32)
    buf[:25] = flag_bytes
    buf[25:] = b"\x5A" * 7
    s = list(struct.unpack_from("<4Q", buf))

    for r in range(12):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1 << 64) - 1)
        s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1 << 64) - 1)
        s[2] ^= r + 4
        s[3] = rol64(s[3], 3) ^ s[2]
        s[0] ^= s[3]
        s[2] ^= s[1]

    out = bytearray()
    while len(out) < out_len:
        chunk = min(32, out_len - len(out))
        out += struct.pack("<4Q", *s)[:chunk]
        s[0] = (s[0] + s[2]) & ((1 << 64) - 1)
        s[1] ^= s[3]
        s[2] = rol64(s[2], 17)
        s[3] = ror64(s[3], 11)
    return bytes(out)


def solve_flag_b(timeout_ms: int) -> bytes:
    try:
        from z3 import BitVec, BitVecVal, Extract, LShR, Solver, ZeroExt, sat
    except ImportError as exc:
        raise RuntimeError("missing z3-solver; install it or pass --use-known-flagb") from exc

    start = time.time()
    flag = [BitVec(f"f{i}", 8) for i in range(25)]
    buf = flag + [BitVecVal(0x5A, 8)] * 7

    def bytes_to_bv64(items):
        value = ZeroExt(56, items[0])
        for j in range(1, 8):
            value = value | (ZeroExt(56, items[j]) << (j * 8))
        return value

    def z3_ror64(x, n):
        return LShR(x, n) | (x << (64 - n))

    def z3_rol64(x, n):
        return (x << n) | LShR(x, 64 - n)

    state = [bytes_to_bv64(buf[i * 8 : (i + 1) * 8]) for i in range(4)]
    for r in range(12):
        state[0] = (z3_ror64(state[0], 8) + state[1]) ^ BitVecVal(r, 64)
        state[1] = z3_rol64(state[1], 3) ^ state[0]
        state[2] = (z3_ror64(state[2], 8) + state[3]) ^ BitVecVal(r + 4, 64)
        state[3] = z3_rol64(state[3], 3) ^ state[2]
        state[0] = state[0] ^ state[3]
        state[2] = state[2] ^ state[1]

    material = []
    squeeze = list(state)
    for _ in range(3):
        for word in squeeze:
            for j in range(8):
                material.append(Extract(j * 8 + 7, j * 8, word))
        squeeze[0] = squeeze[0] + squeeze[2]
        squeeze[1] = squeeze[1] ^ squeeze[3]
        squeeze[2] = z3_rol64(squeeze[2], 17)
        squeeze[3] = z3_ror64(squeeze[3], 11)

    solver = Solver()
    solver.set("timeout", timeout_ms)

    for i, b in enumerate(KNOWN_MATERIAL_0_16):
        solver.add(material[i] == BitVecVal(b, 8))

    seed_bytes = struct.pack("<4I", *KNOWN_SEEDS)
    for i, b in enumerate(seed_bytes):
        solver.add(material[80 + i] == BitVecVal(b, 8))

    for i, b in enumerate(KNOWN_MATERIAL_60_64):
        solver.add(material[60 + i] == BitVecVal(b, 8))

    print(f"[*] Z3 solving flagB, timeout={timeout_ms} ms")
    result = solver.check()
    elapsed = time.time() - start
    if result != sat:
        raise RuntimeError(f"Z3 did not solve flagB: {result} after {elapsed:.1f}s")

    model = solver.model()
    flag_b = bytes(model.eval(flag[i]).as_long() for i in range(25))
    print(f"[+] Z3 solved flagB in {elapsed:.1f}s")
    return flag_b


def assert_flag_b_constraints(flag_b: bytes) -> None:
    material = expand_key_material(flag_b, 96)
    if material[:16] != KNOWN_MATERIAL_0_16:
        raise AssertionError("flagB failed material[0:16] constraint")
    if material[80:96] != struct.pack("<4I", *KNOWN_SEEDS):
        raise AssertionError("flagB failed material[80:96] seed constraint")
    if material[60:64] != KNOWN_MATERIAL_60_64:
        raise AssertionError("flagB failed material[60:64] constraint")


def compute_const_xor_key() -> bytes:
    kpt_raw = struct.pack(
        "<6I", 0x00000001, 0x00000002, 0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0
    )
    piece0 = zlib.crc32(kpt_raw) & 0xFFFFFFFF
    iv_a2 = 0x8BADF00D
    piece1 = 0xDEADBEEF ^ ror32(iv_a2, 13)
    piece2 = 0x67452301 ^ 0x3CC35AA5
    seed = piece0 ^ piece1 ^ piece2

    key = bytearray(16)
    s = seed
    for i in range(4):
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
        struct.pack_into("<I", key, i * 4, s)
    return bytes(key)


def ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def compute_ipc_material() -> bytes:
    key = compute_const_xor_key()
    return bytes(key[(i * 5 + 3) & 0x0F] ^ ((0xC3 + i * 0x29) & 0xFF) for i in range(16))


def key_schedule_b(flag_b: bytes, so_key: bytes) -> dict[str, object]:
    material = bytearray(128)
    material[:96] = expand_key_material(flag_b, 96)
    for i in range(16):
        material[96 + i] = material[i] ^ so_key[i]

    ipc = compute_ipc_material()
    for i in range(16):
        material[112 + i] = material[32 + i] ^ ipc[i]

    round_keys = [
        u32(material, i * 4) ^ u32(material, 112 + ((i & 3) * 4)) for i in range(16)
    ]

    configs = []
    for i in range(16):
        b = material[64 + i]
        configs.append(
            {
                "ss": (b >> 0) & 3,
                "sp": (b >> 2) & 3,
                "mm": (b >> 4) & 3,
                "nm": (b >> 6) & 3,
            }
        )

    seeds = [u32(material, 80 + i * 4) for i in range(4)]
    delta = u32(material, 96) ^ u32(material, 112)
    check = round_keys[15] ^ u32(so_key, 12)
    return {
        "material": bytes(material),
        "round_keys": round_keys,
        "configs": configs,
        "seeds": seeds,
        "delta": delta,
        "check": check,
    }


def gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result


def gf_pow(base: int, exp: int) -> int:
    result = 1
    while exp:
        if exp & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exp >>= 1
    return result


def generate_sbox(seed: int) -> list[int]:
    sbox = list(range(256))
    xs = seed & 0xFFFFFFFF
    for i in range(255, 0, -1):
        xs ^= (xs << 13) & 0xFFFFFFFF
        xs ^= xs >> 17
        xs ^= (xs << 5) & 0xFFFFFFFF
        j = xs % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


def crc32_16(data: bytes) -> int:
    table = [
        0x00000000,
        0x1DB71064,
        0x3B6E20C8,
        0x26D930AC,
        0x76DC4190,
        0x6B6B51F4,
        0x4DB26158,
        0x5005713C,
        0xEDB88320,
        0xF00F9344,
        0xD6D6A3E8,
        0xCB61B38C,
        0x9B64C2B0,
        0x86D3D2D4,
        0xA00AE278,
        0xBDBDF21C,
    ]
    crc = 0xFFFFFFFF
    for b in data[:16]:
        crc ^= b
        crc = ((crc >> 4) ^ table[crc & 0x0F]) & 0xFFFFFFFF
        crc = ((crc >> 4) ^ table[crc & 0x0F]) & 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


def spn_encrypt(iv: bytes, schedule: dict[str, object]) -> bytes:
    state = list(iv)
    round_keys = schedule["round_keys"]
    configs = schedule["configs"]
    delta = schedule["delta"]
    seeds = schedule["seeds"]
    assert isinstance(round_keys, list)
    assert isinstance(configs, list)
    assert isinstance(delta, int)
    assert isinstance(seeds, list)

    sboxes = [generate_sbox(s) for s in seeds]
    state_crc_mix = 0
    for rnd in range(16):
        if rnd == 8:
            state_crc_mix = crc32_16(bytes(state))

        dyn_key = round_keys[rnd]
        if rnd >= 8:
            dyn_key ^= u32(bytes(state[:4]), 0)
            dyn_key ^= state_crc_mix

        cfg = configs[rnd]
        sel = cfg["ss"] if rnd < 8 else (cfg["ss"] ^ state[0]) & 3
        state = [sboxes[sel][b] for b in state]

        tmp = state[:]
        for row in range(4):
            shift = SHIFTS[cfg["sp"]][row] & 3
            for col in range(4):
                state[row + 4 * col] = tmp[row + 4 * ((col + shift) % 4)]

        mixed = [0] * 16
        matrix = MDS[cfg["mm"]]
        for col in range(4):
            inp = state[col * 4 : col * 4 + 4]
            for i in range(4):
                v = 0
                for j in range(4):
                    v ^= gf_mul(matrix[i][j], inp[j])
                mixed[col * 4 + i] = v
        state = mixed

        power = NL_POWER[cfg["nm"] & 3]
        rc = (delta >> ((rnd % 4) * 8)) & 0xFF
        state = [gf_pow(b ^ rc ^ (rnd & 0xFF), power) for b in state]

        key_bytes = struct.pack("<I", dyn_key & 0xFFFFFFFF)
        state = [state[i] ^ key_bytes[i & 3] for i in range(16)]

    return bytes(state)


def interleave(flag_a: bytes, flag_b: bytes) -> bytes:
    out = bytearray(50)
    for i in range(25):
        out[i * 2] = flag_a[i]
        out[i * 2 + 1] = flag_b[i]
    return bytes(out)


def c_bytes(data: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in data)


def maybe_extract_source_diagnostics(so_key: bytes, schedule: dict[str, object]) -> list[str]:
    key_expand = ROOT / "app" / "src" / "main" / "cpp" / "src" / "key_expand.c"
    jni_entry = ROOT / "app" / "src" / "main" / "cpp" / "src" / "jni_entry.c"
    if not key_expand.exists() or not jni_entry.exists():
        return []

    lines: list[str] = []
    cx_key = compute_const_xor_key()
    check = schedule["check"]
    assert isinstance(check, int)

    key_text = key_expand.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"EXPECTED_SOKEY_CHECK_ENC\s*=\s*(0x[0-9a-fA-F]+)u", key_text)
    if m:
        current_enc = int(m.group(1), 16)
        current_plain = current_enc ^ u32(cx_key, 0)
        needed_enc = check ^ u32(cx_key, 0)
        status = "MATCH" if current_plain == check else "MISMATCH"
        lines.append(
            f"source EXPECTED_SOKEY_CHECK: {current_plain:#010x} "
            f"({status}; needed_enc={needed_enc:#010x})"
        )

    jni_text = jni_entry.read_text(encoding="utf-8", errors="replace")
    for name, final_state in (
        ("ENC_EXPECTED_STATE_ENC", spn_encrypt(IV1, schedule)),
        ("ENC_EXPECTED_STATE2_ENC", spn_encrypt(IV2, schedule)),
    ):
        current = extract_c_array(jni_text, name)
        if current is None:
            continue
        needed_plain = bytes(final_state[i] ^ so_key[i] for i in range(16))
        needed_enc = bytes(needed_plain[i] ^ cx_key[i & 0x0F] for i in range(16))
        status = "MATCH" if current == needed_enc else "MISMATCH"
        lines.append(f"source {name}: {status}; needed=[{c_bytes(needed_enc)}]")
    return lines


def extract_c_array(text: str, name: str) -> bytes | None:
    m = re.search(name + r"\[STATE_LEN\]\s*=\s*\{([^}]+)\}", text, re.S)
    if not m:
        return None
    values = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1))]
    if len(values) != 16:
        return None
    return bytes(values)


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only KCTF2026 keygen")
    parser.add_argument(
        "apk",
        nargs="?",
        default=str(DEFAULT_APK),
        help="Path to app-release.apk",
    )
    parser.add_argument(
        "--use-known-flagb",
        action="store_true",
        help="Skip Z3 and use the already recovered flagB bytes.",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=1_800_000,
        help="Z3 timeout in milliseconds.",
    )
    parser.add_argument(
        "--no-diagnostics",
        action="store_true",
        help="Do not compare derived values with adjacent C source constants.",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] = sys.argv[1:]) -> int:
    args = parse_args(argv)
    apk_path = Path(args.apk)

    print("=" * 64)
    print("  KCTF2026 Read-Only Keygen")
    print("=" * 64)

    so = read_apk_so(apk_path)
    so_key, crc, source = derive_sokey(so)
    print(f"apk={apk_path}")
    print(f"libkctf.so={len(so)} bytes")
    print(f"soKey_source={source}")
    print(f"guard_crc32={crc:08x}")
    print(f"soKey={so_key.hex()}")

    if args.use_known_flagb:
        flag_b = KNOWN_FLAG_B
        print("[*] flagB mode: known recovered value")
    else:
        flag_b = solve_flag_b(args.timeout_ms)

    assert_flag_b_constraints(flag_b)
    if flag_b == KNOWN_FLAG_B:
        print("[+] flagB matches current recovered value")
    else:
        print("[!] flagB differs from embedded known value but satisfies constraints")

    flag_a = build_flag_a(so_key)
    final_flag = interleave(flag_a, flag_b)

    schedule = key_schedule_b(flag_b, so_key)
    print(f"flagA={flag_a.hex()}")
    print(f"flagB={flag_b.hex()}")
    print(f"flag={final_flag.hex()}")
    print(f"schemeB_clean_check={schedule['check']:#010x}")
    print(f"schemeB_clean_spn_iv1={spn_encrypt(IV1, schedule).hex()}")
    print(f"schemeB_clean_spn_iv2={spn_encrypt(IV2, schedule).hex()}")

    if not args.no_diagnostics:
        diagnostics = maybe_extract_source_diagnostics(so_key, schedule)
        if diagnostics:
            print()
            print("[diagnostics] Adjacent source constants, read-only:")
            for line in diagnostics:
                print(f"  {line}")
            print("[diagnostics] MISMATCH means the APK/source constants are stale; this script did not patch them.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
