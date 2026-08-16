#!/usr/bin/env python3
"""
KCTF2026 read-only keygen.

This script does not patch, rebuild, or modify the APK.  It only reads the APK,
recovers the two 25-byte halves, and prints the final 50-byte hex input.

Default behavior:
  - derive soKey from the APK's stable guard section;
  - solve flagB with recovered oracle/material constraints using Bitwuzla/Z3;
  - derive flagA from the recovered BB offsets used by the current release;
  - interleave flagA and flagB.

Use --use-known-flagb for a quick maintenance run that skips SMT solving.
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
MASK64 = (1 << 64) - 1
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
    "BB0_BRANCH_OFF": 0x6F60,
    "BB1_OFF": 0x6F68,
    "BB4_BRANCH_OFF": 0x72D4,
    "DEAD_BLOCK_OFF": 0x72D8,
    "BB5_OFF": 0x72E8,
    "BB6_ADR_OFF": 0x7464,
    "BB7_ENTRY_OFF": 0x746C,
}
# Scheme-B constraints recovered from the oracle, material checks, and the
# simplified material[8:16] mid-tag dataflow.  material[8:16] is intentionally
# not embedded as a public plaintext constraint.
KNOWN_SEEDS = (0x24BE739F, 0x966CDDA1, 0xBB2307B9, 0xC9FDCDA7)
KNOWN_MATERIAL_0_8 = bytes.fromhex("c1914230477ab658")
KNOWN_MATERIAL_MID_TAG = 0x56613E13
KNOWN_FAKE_SYNDROME = 0x30
KNOWN_A_SHARE = 0x58

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


FLAG_A_PERM = [
    7, 2, 19, 0, 14, 23, 5, 11, 21, 3, 17, 8, 24,
    1, 12, 6, 20, 10, 4, 22, 15, 9, 18, 13, 16,
]


def rol8(x, n):
    n &= 7
    x &= 0xFF
    return x if n == 0 else (((x << n) | (x >> (8 - n))) & 0xFF)


def encode_flag_a(plain, so_key):
    out = bytearray(25)
    prev = so_key[7] ^ 0xC3
    for i, j in enumerate(FLAG_A_PERM):
        mix_base = (prev + i * 0x31 + so_key[(i * 7 + 1) & 0x0F]) & 0xFF
        mix = rol8(mix_base, i)
        out[j] = ((plain[i] ^ so_key[(i * 5 + 3) & 0x0F]) + mix) & 0xFF
        prev = ((plain[i] + mix) & 0xFF) ^ ((0x5A + i * 0x23) & 0xFF)
    return bytes(out)


def decode_flag_a(encoded, so_key):
    out = bytearray(25)
    prev = so_key[7] ^ 0xC3
    for i, j in enumerate(FLAG_A_PERM):
        mix_base = (prev + i * 0x31 + so_key[(i * 7 + 1) & 0x0F]) & 0xFF
        mix = rol8(mix_base, i)
        out[i] = ((encoded[j] - mix) & 0xFF) ^ so_key[(i * 5 + 3) & 0x0F]
        prev = ((out[i] + mix) & 0xFF) ^ ((0x5A + i * 0x23) & 0xFF)
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


def solve_flag_b(timeout_ms: int, solver_name: str, so_key: bytes) -> bytes:
    """Solve the missing material[8:16] state via a simplified BV model.

    Public/recoverable constraints used here:
      - material[0:8] from the oracle material-head decoder;
      - material[80:96] from oracle seeds;
      - material_mid_tag from the native MBA tag check;
      - fake material syndrome, which must be a specific non-zero mismatch;
      - final ARX preimage padding flagB || 0x5a * 7;
      - material[60:64] as a final sanity check.
    """
    solver, s1, preimage_bytes = build_s1_z3_model(timeout_ms, so_key)
    selected = solver_name
    if selected == "auto":
        selected = "bitwuzla"

    start = time.time()
    print(f"[*] {selected} solving material[8:16], timeout={timeout_ms} ms")

    if selected == "z3":
        try:
            from z3 import sat
        except ImportError as exc:
            raise RuntimeError("missing z3-solver") from exc
        result = solver.check()
        elapsed = time.time() - start
        if result != sat:
            raise RuntimeError(f"Z3 did not solve material[8:16]: {result} after {elapsed:.1f}s")
        model = solver.model()
        s1_value = model.eval(s1).as_long()
        flag_b = bytes(model.eval(preimage_bytes[i]).as_long() for i in range(25))
        print(f"[+] Z3 solved material[8:16] in {elapsed:.1f}s")
        print(f"[+] material[8:16]={s1_value.to_bytes(8, 'little').hex()}")
        return flag_b

    if selected == "bitwuzla":
        try:
            import bitwuzla
        except ImportError as exc:
            raise RuntimeError("missing bitwuzla Python package; pip install bitwuzla") from exc
        mgr = bitwuzla.TermManager()
        opts = bitwuzla.Options()
        opts.set(bitwuzla.Option.PRODUCE_MODELS, True)
        opts.set(bitwuzla.Option.TIME_LIMIT_PER, timeout_ms)
        parser = bitwuzla.Parser(mgr, opts)
        parser.parse(normalize_z3_smt2_for_bitwuzla(solver.to_smt2()).replace("(check-sat)", ""), parse_file=False)
        bz = parser.bitwuzla()
        result = bz.check_sat()
        elapsed = time.time() - start
        if str(result) != "sat":
            raise RuntimeError(f"Bitwuzla did not solve material[8:16]: {result} after {elapsed:.1f}s")
        funs = {str(f): f for f in parser.get_declared_funs()}
        term = funs.get("s1")
        if term is None:
            raise RuntimeError("Bitwuzla model did not expose s1")
        bits = str(bz.get_value(term))
        s1_value = int(bits[2:], 2)
        flag_b = recover_flag_b_from_s1(s1_value)
        print(f"[+] Bitwuzla solved material[8:16] in {elapsed:.1f}s")
        print(f"[+] material[8:16]={s1_value.to_bytes(8, 'little').hex()}")
        return flag_b

    if selected == "cvc5":
        try:
            import cvc5
        except ImportError as exc:
            raise RuntimeError("missing cvc5 Python package; pip install cvc5") from exc
        cvc = cvc5.Solver()
        cvc.setOption("produce-models", "true")
        cvc.setOption("tlimit-per", str(timeout_ms))
        parser = cvc5.InputParser(cvc)
        text = normalize_z3_smt2_for_bitwuzla(solver.to_smt2())
        parser.setStringInput(cvc5.InputLanguage.SMT_LIB_2_6, text, "material_8_16.smt2")
        symbols = parser.getSymbolManager()
        result = None
        while True:
            cmd = parser.nextCommand()
            if cmd.isNull():
                break
            out = cmd.invoke(cvc, symbols)
            if str(cmd).startswith("(check-sat"):
                result = out
                break
        elapsed = time.time() - start
        if str(result) != "sat":
            raise RuntimeError(f"cvc5 did not solve material[8:16]: {result} after {elapsed:.1f}s")
        funs = {str(f): f for f in symbols.getDeclaredTerms()}
        term = funs.get("s1")
        if term is None:
            raise RuntimeError("cvc5 model did not expose s1")
        bits = str(cvc.getValue(term))
        s1_value = int(bits[2:], 2)
        flag_b = recover_flag_b_from_s1(s1_value)
        print(f"[+] cvc5 solved material[8:16] in {elapsed:.1f}s")
        print(f"[+] material[8:16]={s1_value.to_bytes(8, 'little').hex()}")
        return flag_b

    raise ValueError(f"unsupported solver: {solver_name}")



def normalize_z3_smt2_for_bitwuzla(text: str) -> str:
    # Z3 prints fixed rotates as (ext_rotate_left x (_ bvN W)); Bitwuzla
    # accepts the SMT-LIB indexed form ((_ rotate_left N) x).
    import re
    pattern = re.compile(r"\(ext_rotate_(left|right) ([^()]+|\([^()]*\)) \(_ bv(\d+) \d+\)\)")
    prev = None
    while prev != text:
        prev = text
        text = pattern.sub(lambda m: f"((_ rotate_{m.group(1)} {m.group(3)}) {m.group(2)})", text)
    if "(set-logic" not in text[:512]:
        text = "(set-logic QF_BV)\n" + text
    return text

def build_s1_z3_model(timeout_ms: int, so_key: bytes):
    try:
        from z3 import BitVec, BitVecVal, Concat, Extract, LShR, Solver, ZeroExt
    except ImportError as exc:
        raise RuntimeError("z3-solver is required to build the SMT model") from exc

    def bv32(v: int):
        return BitVecVal(v & 0xFFFFFFFF, 32)

    def bv64(v: int):
        return BitVecVal(v & MASK64, 64)

    def byte32(x, i: int):
        return Extract(8 * i + 7, 8 * i, x)

    def pack4(bs):
        return Concat(bs[3], bs[2], bs[1], bs[0])

    def xtime(a):
        return (a << 1) ^ (LShR(a, 7) * BitVecVal(0x1B, 8))

    def gf_mul_const(a, c: int):
        r = BitVecVal(0, 8)
        x = a
        while c:
            if c & 1:
                r = r ^ x
            x = xtime(x)
            c >>= 1
        return r

    def mds32(x):
        a = [byte32(x, i) for i in range(4)]
        return pack4([
            gf_mul_const(a[0], 2) ^ gf_mul_const(a[1], 3) ^ a[2] ^ a[3],
            a[0] ^ gf_mul_const(a[1], 2) ^ gf_mul_const(a[2], 3) ^ a[3],
            a[0] ^ a[1] ^ gf_mul_const(a[2], 2) ^ gf_mul_const(a[3], 3),
            gf_mul_const(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul_const(a[3], 2),
        ])

    def inv_mds32(x):
        a = [byte32(x, i) for i in range(4)]
        return pack4([
            gf_mul_const(a[0], 0x0E) ^ gf_mul_const(a[1], 0x0B) ^ gf_mul_const(a[2], 0x0D) ^ gf_mul_const(a[3], 0x09),
            gf_mul_const(a[0], 0x09) ^ gf_mul_const(a[1], 0x0E) ^ gf_mul_const(a[2], 0x0B) ^ gf_mul_const(a[3], 0x0D),
            gf_mul_const(a[0], 0x0D) ^ gf_mul_const(a[1], 0x09) ^ gf_mul_const(a[2], 0x0E) ^ gf_mul_const(a[3], 0x0B),
            gf_mul_const(a[0], 0x0B) ^ gf_mul_const(a[1], 0x0D) ^ gf_mul_const(a[2], 0x09) ^ gf_mul_const(a[3], 0x0E),
        ])

    def fbox32(x, k):
        x = x ^ k
        x = x * bv32(0x045D9F3B)
        x = x ^ LShR(x, 16)
        x = x * bv32(0x119DE1F3)
        x = x ^ LShR(x, 15)
        return x

    def feistel32(x, k):
        l = Extract(15, 0, x)
        r = Extract(31, 16, x)
        l = l ^ Extract(15, 0, fbox32(ZeroExt(16, r), k))
        r = r ^ Extract(15, 0, fbox32(ZeroExt(16, l), k ^ bv32(0x9E37)))
        return Concat(r, l)

    def zrol32(x, n: int):
        n &= 31
        return x if n == 0 else ((x << n) | LShR(x, 32 - n))

    def zrol64(x, n: int):
        n &= 63
        return x if n == 0 else ((x << n) | LShR(x, 64 - n))

    def zror64(x, n: int):
        n &= 63
        return x if n == 0 else (LShR(x, n) | (x << (64 - n)))

    def zrol8(x, n: int):
        n &= 7
        return x if n == 0 else ((x << n) | LShR(x, 8 - n))

    def ch32(x, y, z, salt: int):
        yy = y ^ bv32((salt * 0x01010101) & 0xFFFFFFFF)
        zz = z ^ bv32(rol32(salt, 7))
        out = (x & yy) ^ (~x & zz)
        return out ^ ((bv32(salt) ^ zrol32(x, 3)) * bv32(0x045D9F3B))

    def maj32(x, y, z, salt: int):
        a = x ^ bv32(rol32(salt, 11))
        b = y ^ bv32((salt * 0x9E3779B1) & 0xFFFFFFFF)
        c = z ^ zrol32(bv32(salt) ^ x, 19)
        return (a & b) ^ (a & c) ^ (b & c)

    def poly32(x, y, z, salt: int):
        p = (x ^ zrol32(y, 5)) + ((z | bv32(1)) * bv32(salt | 1))
        q = (p & zrol32(x, 11)) ^ (~p & zrol32(y ^ z, 17))
        q = q + ((x ^ z) * bv32(0x119DE1F3))
        return q

    def midtag(s1):
        seed_bytes = struct.pack("<4I", *KNOWN_SEEDS)
        lo = Extract(31, 0, s1)
        hi = Extract(63, 32, s1)
        a = lo ^ bv32(u32(so_key, 0))
        b = hi ^ bv32(u32(so_key, 4))
        c = bv32(u32(KNOWN_MATERIAL_0_8, 0) ^ u32(seed_bytes, 8))
        d = bv32(u32(KNOWN_MATERIAL_0_8, 4) ^ u32(seed_bytes, 12))
        for r in range(4):
            sw = bv32(u32(seed_bytes, (r & 3) * 4))
            salt = (0x7E3A19C5 ^ (r * 0x045D9F3B) ^ (KNOWN_A_SHARE * 0x01010101)) & 0xFFFFFFFF
            ch = ch32(a ^ sw, b, c, salt ^ 0xD6E8FEB8)
            maj = maj32(a, c ^ sw, d, salt ^ 0xC2B2AE35)
            poly = poly32(b ^ sw, c + bv32(salt), d ^ bv32(KNOWN_A_SHARE), salt ^ 0x165667B1)
            f = fbox32((b ^ ch) ^ zrol32(c ^ maj, r + 3), (sw ^ poly) ^ d)
            g = mds32((a ^ maj) ^ f ^ poly)
            feed = (a & zrol32(b, r + 5)) ^ (~b & zrol32(c ^ d ^ ch, r + 1))
            a = zrol32(a + (g ^ feed), 5 + (r & 7))
            b = zrol32(b + (a * bv32(0x9E3779B1 + r * 2)), 11 + r) ^ inv_mds32(g) ^ ch
            c = (c ^ zrol32(a ^ poly, r + 7)) + (b ^ sw ^ maj)
            d = zrol32(d + (c ^ ch ^ LShR(a, (r & 7) + 1)), 3 + ((r * 5) & 15))
        x = (a ^ zrol32(b, 13)) + (c ^ zrol32(d, 19))
        x = x ^ bv32(KNOWN_A_SHARE * 0x01020408)
        return x

    s1 = BitVec("s1", 64)
    solver = Solver()
    solver.set("timeout", timeout_ms)
    solver.add(midtag(s1) == bv32(KNOWN_MATERIAL_MID_TAG))
    seed_bytes = struct.pack("<4I", *KNOWN_SEEDS)
    solver.add(Extract(63, 32, zror64(bv64(rol64(u64(seed_bytes, 8), 22)), 11)) == bv32(u32(KNOWN_MATERIAL_60_64, 0)))

    def fake_syndrome(s1_term):
        cx_key = compute_const_xor_key()
        hint_enc = bytes(
            [
                0xB2, 0x71, 0x0E, 0x5D, 0x93, 0x42, 0xC8, 0x1F,
                0x2A, 0xE4, 0x77, 0x90, 0x5C, 0x39, 0xA6, 0xD1,
            ]
        )
        hint = [
            (hint_enc[i] ^ cx_key[i & 0x0F] ^ ((KNOWN_A_SHARE + i * 0x2B) & 0xFF)) & 0xFF
            for i in range(16)
        ]
        seed_bytes = struct.pack("<4I", *KNOWN_SEEDS)
        material_bytes = (
            [BitVecVal(b, 8) for b in KNOWN_MATERIAL_0_8]
            + [Extract(8 * i + 7, 8 * i, s1_term) for i in range(8)]
            + [BitVecVal(b, 8) for b in struct.pack("<Q", ror64(u64(seed_bytes, 0), 34))]
            + [BitVecVal(b, 8) for b in struct.pack("<Q", rol64(u64(seed_bytes, 8), 22))]
        )
        syndrome = BitVecVal(((KNOWN_A_SHARE + 0x6D) & 0xFF) ^ KNOWN_MATERIAL_0_8[7], 8)
        for i in range(16):
            lane = material_bytes[8 + ((i * 5 + 3) & 0x0F)]
            d = lane ^ BitVecVal(hint[i], 8)
            echo = zrol8(material_bytes[16 + ((i * 3 + 1) & 0x0F)], i + 1)
            d = d ^ echo
            syndrome = syndrome + d + BitVecVal((i * 0x17) & 0xFF, 8)
            syndrome = zrol8(syndrome, (i & 3) + 1)
            syndrome = syndrome ^ ((d * BitVecVal(0x3D, 8)) + BitVecVal(i, 8))
        return syndrome

    solver.add(fake_syndrome(s1) == BitVecVal(KNOWN_FAKE_SYNDROME, 8))

    state = recover_initial_state_terms(s1, bv64, zrol64, zror64)
    preimage_bytes = [Extract(8 * i + 7, 8 * i, word) for word in state for i in range(8)]
    for i in range(25, 32):
        solver.add(preimage_bytes[i] == BitVecVal(0x5A, 8))
    return solver, s1, preimage_bytes


def recover_initial_state_terms(s1, bv64, zrol64, zror64):
    seed_bytes = struct.pack("<4I", *KNOWN_SEEDS)
    s0 = u64(KNOWN_MATERIAL_0_8, 0)
    s2 = ror64(u64(seed_bytes, 0), 34)
    s3 = rol64(u64(seed_bytes, 8), 22)
    state = [bv64(s0), s1, bv64(s2), bv64(s3)]
    for r in range(11, -1, -1):
        e0, e1, e2, e3 = state
        d3 = e3
        d1 = e1
        d0 = e0 ^ e3
        d2 = e2 ^ e1
        c3 = zror64(d3 ^ d2, 3)
        c2 = zrol64((d2 ^ bv64(r + 4)) - c3, 8)
        c1 = zror64(d1 ^ d0, 3)
        c0 = zrol64((d0 ^ bv64(r)) - c1, 8)
        state = [c0, c1, c2, c3]
    return state


def recover_flag_b_from_s1(s1_value: int) -> bytes:
    seed_bytes = struct.pack("<4I", *KNOWN_SEEDS)
    state = [
        u64(KNOWN_MATERIAL_0_8, 0),
        s1_value & MASK64,
        ror64(u64(seed_bytes, 0), 34),
        rol64(u64(seed_bytes, 8), 22),
    ]
    for r in range(11, -1, -1):
        e0, e1, e2, e3 = state
        d3 = e3
        d1 = e1
        d0 = e0 ^ e3
        d2 = e2 ^ e1
        c3 = ror64(d3 ^ d2, 3)
        c2 = rol64(((d2 ^ (r + 4)) - c3) & MASK64, 8)
        c1 = ror64(d1 ^ d0, 3)
        c0 = rol64(((d0 ^ r) - c1) & MASK64, 8)
        state = [c0, c1, c2, c3]
    buf = struct.pack("<4Q", *state)
    if buf[25:] != b"\x5A" * 7:
        raise RuntimeError("SMT result failed flagB padding check")
    return buf[:25]

def assert_flag_b_constraints(flag_b: bytes, so_key: bytes) -> None:
    material = expand_key_material(flag_b, 96)
    seed_bytes = struct.pack("<4I", *KNOWN_SEEDS)
    if material[:8] != KNOWN_MATERIAL_0_8:
        raise AssertionError("flagB failed material[0:8] constraint")
    if material[80:96] != seed_bytes:
        raise AssertionError("flagB failed material[80:96] seed constraint")
    if material[60:64] != KNOWN_MATERIAL_60_64:
        raise AssertionError("flagB failed material[60:64] constraint")
    if derive_material_mid_tag_int(material[:16], seed_bytes, so_key, KNOWN_A_SHARE) != KNOWN_MATERIAL_MID_TAG:
        raise AssertionError("flagB failed material[8:16] mid-tag constraint")
    if derive_fake_syndrome_int(flag_b, KNOWN_A_SHARE) != KNOWN_FAKE_SYNDROME:
        raise AssertionError("flagB failed fake syndrome constraint")


def derive_fake_syndrome_int(flag_b: bytes, a_share: int) -> int:
    material = expand_key_material(flag_b, 32)
    cx_key = compute_const_xor_key()
    hint_enc = bytes(
        [
            0xB2, 0x71, 0x0E, 0x5D, 0x93, 0x42, 0xC8, 0x1F,
            0x2A, 0xE4, 0x77, 0x90, 0x5C, 0x39, 0xA6, 0xD1,
        ]
    )
    hint = bytearray(hint_enc[i] ^ cx_key[i & 0x0F] for i in range(16))
    for i in range(16):
        hint[i] ^= (a_share + i * 0x2B) & 0xFF

    syndrome = ((a_share + 0x6D) & 0xFF) ^ material[7]
    for i in range(16):
        lane = material[8 + ((i * 5 + 3) & 0x0F)]
        d = lane ^ hint[i]
        echo = rol8(material[16 + ((i * 3 + 1) & 0x0F)], i + 1)
        d ^= echo
        syndrome = (syndrome + ((d + i * 0x17) & 0xFF)) & 0xFF
        syndrome = rol8(syndrome, (i & 3) + 1)
        syndrome ^= (d * 0x3D + i) & 0xFF
    return syndrome & 0xFF


def derive_material_mid_tag_int(material: bytes, seeds: bytes, so_key: bytes, a_share: int) -> int:
    def mds32(x):
        a0, a1, a2, a3 = x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF
        b0 = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
        b1 = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
        b2 = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
        b3 = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)
        return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) & 0xFFFFFFFF

    def inv_mds32(x):
        a0, a1, a2, a3 = x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF
        b0 = gf_mul(a0, 0x0E) ^ gf_mul(a1, 0x0B) ^ gf_mul(a2, 0x0D) ^ gf_mul(a3, 0x09)
        b1 = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0E) ^ gf_mul(a2, 0x0B) ^ gf_mul(a3, 0x0D)
        b2 = gf_mul(a0, 0x0D) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0E) ^ gf_mul(a3, 0x0B)
        b3 = gf_mul(a0, 0x0B) ^ gf_mul(a1, 0x0D) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0E)
        return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) & 0xFFFFFFFF

    def fbox32(x, k):
        x = (x ^ k) & 0xFFFFFFFF
        x = (x * 0x045D9F3B) & 0xFFFFFFFF
        x ^= x >> 16
        x = (x * 0x119DE1F3) & 0xFFFFFFFF
        x ^= x >> 15
        return x & 0xFFFFFFFF

    def feistel32(x, k):
        l, r = x & 0xFFFF, (x >> 16) & 0xFFFF
        l ^= fbox32(r, k) & 0xFFFF
        r ^= fbox32(l, k ^ 0x9E37) & 0xFFFF
        return (l | (r << 16)) & 0xFFFFFFFF

    def inv_feistel32(x, k):
        l, r = x & 0xFFFF, (x >> 16) & 0xFFFF
        r ^= fbox32(l, k ^ 0x9E37) & 0xFFFF
        l ^= fbox32(r, k) & 0xFFFF
        return (l | (r << 16)) & 0xFFFFFFFF

    def mba_add32(a, b, salt):
        s = a & 0xFFFFFFFF
        c = b & 0xFFFFFFFF
        for _ in range(32):
            ns = (s ^ c) & 0xFFFFFFFF
            c = ((s & c) << 1) & 0xFFFFFFFF
            s = ns
        return inv_feistel32(feistel32(s, salt), salt)

    def mba_xor32(a, b, salt):
        ma = fbox32(salt, 0xA0761D64)
        mb = fbox32(salt ^ 0xE7037ED1, 0x8EBC6AF1)
        t = (inv_mds32(mds32((a ^ ma) & 0xFFFFFFFF) ^ mds32((b ^ mb) & 0xFFFFFFFF)) ^ ma ^ mb) & 0xFFFFFFFF
        return inv_feistel32(feistel32(t, ma ^ mb), ma ^ mb)

    def ch32(x, y, z, salt):
        yy = mba_xor32(y, (salt * 0x01010101) & 0xFFFFFFFF, salt ^ 0xB492B66F)
        zz = mba_xor32(z, rol32(salt, 7), salt ^ 0x9E3779B9)
        out = ((x & yy) ^ ((~x & 0xFFFFFFFF) & zz)) & 0xFFFFFFFF
        return mba_xor32(out, ((salt ^ rol32(x, 3)) * 0x045D9F3B) & 0xFFFFFFFF, salt ^ 0x6A09E667)

    def maj32(x, y, z, salt):
        a = mba_xor32(x, rol32(salt, 11), salt ^ 0xBB67AE85)
        b = mba_xor32(y, (salt * 0x9E3779B1) & 0xFFFFFFFF, salt ^ 0x3C6EF372)
        c = mba_xor32(z, rol32(salt ^ x, 19), salt ^ 0xA54FF53A)
        out = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
        return inv_mds32(mds32(out))

    def poly32(x, y, z, salt):
        p = mba_add32(mba_xor32(x, rol32(y, 5), salt ^ 0x510E527F),
                      ((z | 1) * (salt | 1)) & 0xFFFFFFFF,
                      salt ^ 0x9B05688C)
        q = ((p & rol32(x, 11)) ^ ((~p & 0xFFFFFFFF) & rol32(mba_xor32(y, z, salt ^ 0x1F83D9AB), 17))) & 0xFFFFFFFF
        q = mba_add32(q, (mba_xor32(x, z, salt ^ 0x5BE0CD19) * 0x119DE1F3) & 0xFFFFFFFF,
                      salt ^ 0xC3A5C85C)
        return inv_feistel32(feistel32(q, salt ^ p), salt ^ p)

    a = mba_xor32(u32(material, 8), u32(so_key, 0), 0xD1B54A32)
    b = mba_xor32(u32(material, 12), u32(so_key, 4), 0x94D049BB)
    c = mba_xor32(u32(material, 0), u32(seeds, 8), 0x2545F491)
    d = mba_xor32(u32(material, 4), u32(seeds, 12), 0x9E3779B9)
    for r in range(4):
        sw = u32(seeds, (r & 3) * 4)
        salt = (0x7E3A19C5 ^ (r * 0x045D9F3B) ^ (a_share * 0x01010101)) & 0xFFFFFFFF
        ch = ch32(a ^ sw, b, c, salt ^ 0xD6E8FEB8)
        maj = maj32(a, c ^ sw, d, salt ^ 0xC2B2AE35)
        poly = poly32(b ^ sw, (c + salt) & 0xFFFFFFFF, d ^ a_share, salt ^ 0x165667B1)
        f = fbox32(mba_xor32(b ^ ch, rol32(c ^ maj, r + 3), salt),
                   mba_xor32(sw ^ poly, d, salt ^ 0xA0761D64))
        g = mds32(mba_xor32(a ^ maj, f ^ poly, salt ^ 0xE7037ED1))
        feed = ((a & rol32(b, r + 5)) ^ ((~b & 0xFFFFFFFF) & rol32(c ^ d ^ ch, r + 1))) & 0xFFFFFFFF
        a = rol32(mba_add32(a, mba_xor32(g, feed, salt ^ 0x8EBC6AF1), salt ^ 0xD6E8FEB8),
                  5 + (r & 7))
        b = (rol32(mba_add32(b, (a * (0x9E3779B1 + r * 2)) & 0xFFFFFFFF,
                              salt ^ 0x94D049BB), 11 + r) ^ inv_mds32(g) ^ ch) & 0xFFFFFFFF
        c = mba_add32(c ^ rol32(a ^ poly, r + 7), b ^ sw ^ maj, salt ^ 0xC3A5C85C)
        d = rol32((d + mba_xor32(c ^ ch, a >> ((r & 7) + 1), salt ^ 0x27D4EB2F)) & 0xFFFFFFFF,
                  3 + ((r * 5) & 15))
    x = mba_xor32(a, rol32(b, 13), 0x6A09E667)
    x = mba_add32(x, mba_xor32(c, rol32(d, 19), 0xBB67AE85), 0x3C6EF372)
    x = mba_xor32(x, (a_share * 0x01020408) & 0xFFFFFFFF, 0xA54FF53A)
    return inv_feistel32(feistel32(x, x ^ u32(so_key, 8)), x ^ u32(so_key, 8))


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
    n &= 31
    x &= 0xFFFFFFFF
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF if n else x

def rol32(x: int, n: int) -> int:
    n &= 31
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF if n else x


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
    expected_check = u32(KNOWN_MATERIAL_60_64, 0) ^ u32(so_key, 12)
    diff = check ^ expected_check
    poison = (((diff | ((~diff + 1) & 0xFFFFFFFF)) >> 31) & 1) * 0xDEADBEEF
    delta ^= poison
    return {
        "material": bytes(material),
        "round_keys": round_keys,
        "configs": configs,
        "seeds": seeds,
        "delta": delta,
        "check": check,
        "expected_check": expected_check,
        "check_poison": poison,
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
    expected_check = schedule["expected_check"]
    assert isinstance(expected_check, int)

    key_text = key_expand.read_text(encoding="utf-8", errors="replace")
    jni_text = jni_entry.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"EXPECTED_SOKEY_CHECK_ENC\s*=\s*(0x[0-9a-fA-F]+)u", key_text)
    if m:
        current_enc = int(m.group(1), 16)
        current_plain = current_enc ^ u32(cx_key, 0)
        needed_enc = expected_check ^ u32(cx_key, 0)
        status = "MATCH" if current_plain == expected_check else "MISMATCH"
        lines.append(
            f"source EXPECTED_SOKEY_CHECK: {current_plain:#010x} "
            f"({status}; needed_enc={needed_enc:#010x})"
        )

    m = re.search(r"EXPECTED_FAKE_SYNDROME_ENC\s*=\s*(0x[0-9a-fA-F]+)u", jni_text)
    if m:
        current_enc = int(m.group(1), 16)
        current_plain = current_enc ^ cx_key[0]
        needed_enc = KNOWN_FAKE_SYNDROME ^ cx_key[0]
        status = "MATCH" if current_plain == KNOWN_FAKE_SYNDROME else "MISMATCH"
        lines.append(
            f"source EXPECTED_FAKE_SYNDROME: {current_plain:#04x} "
            f"({status}; needed_enc={needed_enc:#04x})"
        )

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
        default=300_000,
        help="SMT timeout in milliseconds.",
    )
    parser.add_argument(
        "--solver",
        choices=("auto", "bitwuzla", "cvc5", "z3"),
        default="auto",
        help="SMT backend for material[8:16] (auto prefers Bitwuzla).",
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
        flag_b = solve_flag_b(args.timeout_ms, args.solver, so_key)

    assert_flag_b_constraints(flag_b, so_key)
    if flag_b == KNOWN_FLAG_B:
        print("[+] flagB matches current recovered value")
    else:
        print("[!] flagB differs from embedded known value but satisfies constraints")

    flag_a_plain = build_flag_a(so_key)
    flag_a = encode_flag_a(flag_a_plain, so_key)
    final_flag = interleave(flag_a, flag_b)

    schedule = key_schedule_b(flag_b, so_key)
    print(f"flagA={flag_a.hex()}")
    print(f"flagA_decoded={flag_a_plain.hex()}")
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
