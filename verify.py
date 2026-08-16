#!/usr/bin/env python3
"""Local verifier for the current KCTF2026 release model."""
from __future__ import annotations

import base64
import struct
import sys

_VERIFY_ARGV = sys.argv[:]
_cv_argv = [sys.argv[0]]
sys.argv = _cv_argv
import converge as cv
sys.argv = _VERIFY_ARGV

SO_PATH = _VERIFY_ARGV[1] if len(_VERIFY_ARGV) > 1 else cv.find_so()

BB_ADDRS = {
    "BB0_BRANCH_OFF": 0x58C8,
    "BB1_OFF": 0x58D0,
    "BB4_BRANCH_OFF": 0x5C3C,
    "DEAD_BLOCK_OFF": 0x5C40,
    "BB5_OFF": 0x5C50,
    "BB6_ADR_OFF": 0x5DCC,
    "BB7_ENTRY_OFF": 0x5DD4,
}


def main() -> int:
    so_key, crc, elf_data, text_foff, text_vaddr, text_size = cv.derive_sokey(SO_PATH)
    bb_addrs = dict(BB_ADDRS)

    flag_a_plain = cv.build_flag(so_key, bb_addrs)
    flag_a = cv.encode_flag_a(flag_a_plain, so_key)
    assert cv.decode_flag_a(flag_a, so_key) == flag_a_plain
    flag_b = cv.FLAG_B

    _, _, rc, sbox, _, _ = cv.compute_kct_kout(flag_a_plain, so_key, bb_addrs)
    mat_b = cv.expand_key_material(flag_b, 96)
    expected_sokey_check = struct.unpack_from("<I", mat_b, 60)[0] ^ struct.unpack_from("<I", so_key, 12)[0]
    material_share = cv.derive_material_share(flag_b)
    a_share = cv.derive_scheme_a_share(flag_a_plain, bb_addrs, rc, sbox)

    enc_a = cv.compute_enc_expected_a(flag_a_plain, so_key, bb_addrs, rc, sbox, material_share)
    enc_b = cv.compute_enc_expected_b(flag_b, so_key, expected_sokey_check, a_share=a_share, domain=0xB1)
    enc_b2 = cv.compute_enc_expected_b(flag_b, so_key, expected_sokey_check, iv=cv.IV2_B, a_share=a_share, domain=0xB2)

    b_pass, a_pass, _ = cv.verify_python(SO_PATH, so_key, expected_sokey_check, enc_a, enc_b, enc_b2, bb_addrs)
    if not (a_pass and b_pass):
        raise SystemExit(1)

    inter = bytearray(50)
    for i in range(25):
        inter[i * 2] = flag_a[i]
        inter[i * 2 + 1] = flag_b[i]

    print("=" * 50)
    print("verify.py: ALL PASS")
    print("=" * 50)
    print(f"soKey={so_key.hex()}")
    print(f"CRC32(.text)={crc:08x}")
    print(f"Scheme A flag={flag_a.hex()}")
    print(f"Scheme A decoded={flag_a_plain.hex()}")
    print(f"Scheme B flag={flag_b.hex()}")
    print(f"50-byte flag={bytes(inter).hex()}")
    print(f"50-byte flag b64={base64.b64encode(bytes(inter)).decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
