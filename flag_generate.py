#!/usr/bin/env python3
"""
Generate the current KCTF2026 flag from information recoverable by reversing.

The script intentionally does not call challenge internals.  It uses:
  - the APK's libkctf.so guard section to derive soKey;
  - BB offsets recovered from repair_cfg/core_compute;
  - the scheme-B model recovered from the ARX+SPN constraints.
"""
from __future__ import annotations

import struct
import sys
import zipfile
import zlib
from pathlib import Path


APK_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
    "app/build/outputs/apk/release/app-release.apk"
)

GUARD_BYTES = bytes.fromhex(
    "e0cc9cd22041adf2a0d0d5f2e06cf7f2"
    "416e9ed2c18da7f241a7def2e1a9f4f2"
    "020001ca4234c293429416914374c0ca"
    "6300018b6344c393600002cac0035fd6"
    "1f2003d51f2003d51f2003d51f2003d5"
    "1f2003d51f2003d51f2003d51f2003d5"
)

BB = {
    "BB0_BRANCH_OFF": 0x58C8,
    "BB1_OFF": 0x58D0,
    "BB4_BRANCH_OFF": 0x5C3C,
    "DEAD_BLOCK_OFF": 0x5C40,
    "BB5_OFF": 0x5C50,
    "BB6_ADR_OFF": 0x5DCC,
    "BB7_ENTRY_OFF": 0x5DD4,
}
FLAG_B = bytes.fromhex(
    "7ae31b94d256f80c41b7298e63a5df104bc8723d960fe458ad"
)


def read_so(apk_path: Path) -> bytes:
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read("lib/arm64-v8a/libkctf.so")


def sections(elf: bytes) -> dict[str, tuple[int, int]]:
    e_shoff = struct.unpack_from("<Q", elf, 40)[0]
    e_shentsize = struct.unpack_from("<H", elf, 58)[0]
    e_shnum = struct.unpack_from("<H", elf, 60)[0]
    e_shstrndx = struct.unpack_from("<H", elf, 62)[0]
    shstr = elf[e_shoff + e_shstrndx * e_shentsize:e_shoff + (e_shstrndx + 1) * e_shentsize]
    strtab_off = struct.unpack_from("<Q", shstr, 24)[0]
    strtab_size = struct.unpack_from("<Q", shstr, 32)[0]
    strtab = elf[strtab_off:strtab_off + strtab_size]

    out: dict[str, tuple[int, int]] = {}
    for i in range(e_shnum):
        sh = elf[e_shoff + i * e_shentsize:e_shoff + (i + 1) * e_shentsize]
        name_idx = struct.unpack_from("<I", sh, 0)[0]
        end = strtab.index(b"\x00", name_idx)
        name = strtab[name_idx:end].decode()
        off = struct.unpack_from("<Q", sh, 24)[0]
        size = struct.unpack_from("<Q", sh, 32)[0]
        out[name] = (off, size)
    return out


def derive_sokey(so: bytes) -> tuple[bytes, int]:
    sec = sections(so)
    if ".kctfguard" in sec:
        off, size = sec[".kctfguard"]
        guard = so[off:off + size]
    else:
        off, size = sec[".text"]
        text = so[off:off + size]
        pos = text.find(GUARD_BYTES)
        if pos < 0:
            raise RuntimeError("guard bytes not found")
        guard = text[pos:pos + len(GUARD_BYTES)]

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
        key[i * 4:i * 4 + 4] = bytes(
            ((m >> 24) & 0xFF, (m >> 16) & 0xFF, (m >> 8) & 0xFF, m & 0xFF)
        )
    return bytes(key), crc


def flag_a(so_key: bytes) -> bytes:
    out = bytearray(25)

    imm26 = (BB["BB1_OFF"] - BB["BB0_BRANCH_OFF"]) // 4
    struct.pack_into("<I", out, 0, imm26 & 0x03FFFFFF)
    out[4] = 0x01

    b4 = ((BB["BB5_OFF"] - BB["DEAD_BLOCK_OFF"]) // 4) ^ (
        (BB["DEAD_BLOCK_OFF"] - BB["BB4_BRANCH_OFF"]) // 4
    )
    struct.pack_into("<I", out, 5, b4 ^ struct.unpack_from("<I", so_key, 8)[0])

    imm21 = BB["BB7_ENTRY_OFF"] - BB["BB6_ADR_OFF"]
    adr_bits = ((imm21 & 0x3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5)
    struct.pack_into("<I", out, 9, adr_bits ^ struct.unpack_from("<I", so_key, 0)[0])

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

def interleave(a: bytes, b: bytes) -> bytes:
    out = bytearray(50)
    for i in range(25):
        out[i * 2] = a[i]
        out[i * 2 + 1] = b[i]
    return bytes(out)


def main() -> int:
    so = read_so(APK_PATH)
    so_key, crc = derive_sokey(so)
    a_plain = flag_a(so_key)
    a = encode_flag_a(a_plain, so_key)
    flag = interleave(a, FLAG_B)

    print(f"apk={APK_PATH}")
    print(f"guard_crc32={crc:08x}")
    print(f"soKey={so_key.hex()}")
    print(f"flagA={a.hex()}")
    print(f"flagA_decoded={a_plain.hex()}")
    print(f"flagB={FLAG_B.hex()}")
    print(f"flag={flag.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
