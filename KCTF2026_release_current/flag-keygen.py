#!/usr/bin/env python3
"""
KCTF2026 聚焦 material 通道的求解脚本。

本脚本只读公开 APK：从 libkctf.so 派生 soKey，为隐藏的 64 位
`material[8:16]` 通道构建位向量模型，并打印该通道。脚本刻意不恢复、
不打印最终 flag。

当前发布版说明：oracle shellcode 通过 dlsym/SVC 后备的分阶段 XOR 加载器完成映射和解密，并从置换后的 48 字节载荷/表后备存储区返回 32 字节 oracle 结果。下面的常量都是选手可以通过逆向加载器、oracle blob 解码器、material 检查和 native 比较逻辑从 APK 中恢复的公开值；脚本不使用私有构建脚本输出或已知 flag 字节。
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import struct
import time
import zipfile
import zlib
from pathlib import Path


MASK64 = (1 << 64) - 1
DEFAULT_APK = Path(__file__).with_name("KCTF2026.apk")

EXPECTED_APK_SHA256 = "21f932aa6222a37ffc4183861017794c45c3e07a5eb88a7b9050e044256e763f"
EXPECTED_GUARD_CRC32 = 0x3E0695CE
EXPECTED_SOKEY = bytes.fromhex("870573e5f5c63d52862dbd05ab3d9494")

# 当前发布版已恢复的公开 material/oracle 约束。这些数据刻意保持为选手
# 可以从 APK 中提取的同类信息：解码后的加载器/oracle 常量、native 比较、
# 以及由 .kctfguard 派生的 soKey 相关 material。本脚本不消费私有构建期 flag 字节。
MATERIAL_0_8 = bytes.fromhex("c1914230477ab658")
MATERIAL_60_64 = bytes.fromhex("d93d6dee")
MATERIAL_80_96 = bytes.fromhex("9f73be24a1dd6c96b90723bba7cdfdc9")
ORACLE_MATERIAL_HEAD_ENC = bytes.fromhex("fd521311dd1b1725")
ORACLE_TAG = bytes.fromhex("72014429f93dd77c")
EXPECTED_MATERIAL_MID_TAG = 0x92B28E10
EXPECTED_FAKE_SYNDROME = 0xD6
EXPECTED_MATERIAL_LANE_HINT = 0x016EFF8C39C23
KNOWN_A_SHARE = 0xD7


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def rol8(x: int, n: int) -> int:
    n &= 7
    x &= 0xFF
    return x if n == 0 else (((x << n) | (x >> (8 - n))) & 0xFF)


def rol32(x: int, n: int) -> int:
    n &= 31
    x &= 0xFFFFFFFF
    return x if n == 0 else (((x << n) | (x >> (32 - n))) & 0xFFFFFFFF)


def ror32(x: int, n: int) -> int:
    n &= 31
    x &= 0xFFFFFFFF
    return x if n == 0 else (((x >> n) | (x << (32 - n))) & 0xFFFFFFFF)


def rol64(x: int, n: int) -> int:
    n &= 63
    x &= MASK64
    return x if n == 0 else (((x << n) | (x >> (64 - n))) & MASK64)


def ror64(x: int, n: int) -> int:
    n &= 63
    x &= MASK64
    return x if n == 0 else (((x >> n) | (x << (64 - n))) & MASK64)


def read_apk_so(apk_path: Path) -> bytes:
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read("lib/arm64-v8a/libkctf.so")


def parse_elf_sections(elf: bytes) -> dict[str, tuple[int, int]]:
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        raise ValueError("需要 little-endian ELF64 shared object")
    e_shoff = u64(elf, 40)
    e_shentsize = u16(elf, 58)
    e_shnum = u16(elf, 60)
    e_shstrndx = u16(elf, 62)
    shstr = elf[e_shoff + e_shstrndx * e_shentsize:e_shoff + (e_shstrndx + 1) * e_shentsize]
    strtab_off = u64(shstr, 24)
    strtab_size = u64(shstr, 32)
    strtab = elf[strtab_off:strtab_off + strtab_size]

    out: dict[str, tuple[int, int]] = {}
    for i in range(e_shnum):
        sh = elf[e_shoff + i * e_shentsize:e_shoff + (i + 1) * e_shentsize]
        name_idx = struct.unpack_from("<I", sh, 0)[0]
        end = strtab.find(b"\x00", name_idx)
        if end < 0:
            continue
        name = strtab[name_idx:end].decode("ascii", errors="replace")
        out[name] = (u64(sh, 24), u64(sh, 32))
    return out


def derive_sokey(so: bytes) -> tuple[bytes, int]:
    sections = parse_elf_sections(so)
    if ".kctfguard" not in sections:
        raise RuntimeError("未找到 .kctfguard section")
    off, size = sections[".kctfguard"]
    crc = zlib.crc32(so[off:off + size]) & 0xFFFFFFFF
    expand = (
        0xA3F1B28C7D4E5F60,
        0x9C8B7A6D5E4F3021,
        0x1F2E3D4C5B6A7980,
        0xD0E1F2038495A6B7,
    )
    key = bytearray(16)
    for i, e in enumerate(expand):
        m = ((crc ^ e) * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK64
        key[i * 4:i * 4 + 4] = bytes(
            ((m >> 24) & 0xFF, (m >> 16) & 0xFF, (m >> 8) & 0xFF, m & 0xFF)
        )
    return bytes(key), crc


def apk_sha256(apk_path: Path) -> str:
    h = hashlib.sha256()
    with apk_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_const_xor_key() -> bytes:
    kpt_raw = struct.pack(
        "<6I", 0x00000001, 0x00000002, 0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0
    )
    piece0 = zlib.crc32(kpt_raw) & 0xFFFFFFFF
    piece1 = 0xDEADBEEF ^ ror32(0x8BADF00D, 13)
    piece2 = 0x67452301 ^ 0x3CC35AA5
    seed = piece0 ^ piece1 ^ piece2

    key = bytearray(16)
    s = seed
    for i in range(4):
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
        struct.pack_into("<I", key, i * 4, s)
    return bytes(key)


def derive_lane_context_from_oracle_tag(so_key: bytes) -> int:
    lanes: list[int | None] = [None, None, None, None]
    for i in range(8):
        value = (
            ORACLE_TAG[i]
            ^ MATERIAL_80_96[i]
            ^ MATERIAL_80_96[8 + i]
            ^ so_key[(i + 5) & 0x0F]
            ^ ((0xC3 + i * 0x29) & 0xFF)
            ^ ((KNOWN_A_SHARE + i * 0x17) & 0xFF)
        )
        lane = i & 3
        if lanes[lane] is not None and lanes[lane] != value:
            raise RuntimeError("oracle tag 未编码出一致的 lane context")
        lanes[lane] = value
    if any(v is None for v in lanes):
        raise RuntimeError("lane context 不完整")
    return lanes[0] | (lanes[1] << 8) | (lanes[2] << 16) | (lanes[3] << 24)


def derive_material_lane_hint_mask(material0_8: bytes, seeds: bytes, so_key: bytes, a_share: int, lane_ctx: int) -> int:
    x = (u32(seeds, 8) << 32) | u32(so_key, 4)
    x ^= (u32(seeds, 0) << 9) | (u32(so_key, 0) >> 3)
    x ^= u32(material0_8, 0) << 16
    x ^= u32(material0_8, 4) << 1
    x ^= (lane_ctx * 0x9E3779B185EBCA87) & MASK64
    x ^= (a_share * 0x0101010101010101) & MASK64
    x &= MASK64
    x ^= x >> 33
    x = (x * 0xFF51AFD7ED558CCD) & MASK64
    x ^= x >> 33
    x = (x * 0xC4CEB9FE1A85EC53) & MASK64
    x ^= x >> 33
    return x & MASK64


def derive_material_lane_hint(material: bytes, seeds: bytes, so_key: bytes, a_share: int, lane_ctx: int) -> int:
    lane = u64(material, 8)
    mask = derive_material_lane_hint_mask(material[:8], seeds, so_key, a_share, lane_ctx)
    out = 0
    for i in range(46):
        p0 = (i * 7 + 3) & 63
        p1 = (i * 11 + 19) & 63
        p2 = (i * 17 + 5) & 63
        p3 = (i * 23 + 29) & 63
        p4 = (p0 + p2 + i) & 63
        m0 = (i * 5 + 1) & 63
        m1 = (i * 9 + 13) & 63
        m2 = (i * 27 + 31) & 63
        a = ((lane >> p0) ^ (lane >> p1) ^ (mask >> m0) ^ (i * 0xA5 + 0x3D)) & 1
        b = ((lane >> p2) ^ (mask >> m1) ^ (i * 0x3B + 0x71)) & 1
        c = ((lane >> p3) ^ (lane >> p4) ^ (mask >> m2) ^ (i * 0x6D + 0x2F)) & 1
        bit = a ^ (b & c)
        out |= bit << i
    return out & ((1 << 46) - 1)


def material_lane_hint_constraints(so_key: bytes, lane_ctx: int) -> list[tuple[int, int, int, int, int, int, int, int, int]]:
    # Native 中这里表现为更嘈杂的 MBA/Q46 lane-hint 过程。
    # 去混淆后，它等价于 46 条单 bit 二次约束：
    #   a ^ (b & c) == expected
    # bit 位置和常量仍全部来自公开 APK 数据。
    mask = derive_material_lane_hint_mask(MATERIAL_0_8, MATERIAL_80_96, so_key, KNOWN_A_SHARE, lane_ctx)
    constraints: list[tuple[int, int, int, int, int, int, int, int, int]] = []
    for i in range(46):
        p0 = (i * 7 + 3) & 63
        p1 = (i * 11 + 19) & 63
        p2 = (i * 17 + 5) & 63
        p3 = (i * 23 + 29) & 63
        p4 = (p0 + p2 + i) & 63
        m0 = (i * 5 + 1) & 63
        m1 = (i * 9 + 13) & 63
        m2 = (i * 27 + 31) & 63
        a_const = ((mask >> m0) ^ (i * 0xA5 + 0x3D)) & 1
        b_const = ((mask >> m1) ^ (i * 0x3B + 0x71)) & 1
        c_const = ((mask >> m2) ^ (i * 0x6D + 0x2F)) & 1
        expected = (EXPECTED_MATERIAL_LANE_HINT >> i) & 1
        constraints.append((p0, p1, p2, p3, p4, a_const, b_const, c_const, expected))
    return constraints


def public_constraint_selftest(so_key: bytes, guard_crc: int, digest: str) -> dict[str, object]:
    lane_ctx = derive_lane_context_from_oracle_tag(so_key)
    head_projection = encode_oracle_material_head(
        MATERIAL_0_8 + b"\x00" * 8,
        MATERIAL_80_96,
        so_key,
        KNOWN_A_SHARE,
    )
    return {
        "apk_sha256": digest,
        "apk_sha256_ok": digest == EXPECTED_APK_SHA256,
        "guard_crc32": f"{guard_crc:08x}",
        "guard_crc32_ok": guard_crc == EXPECTED_GUARD_CRC32,
        "soKey": so_key.hex(),
        "soKey_ok": so_key == EXPECTED_SOKEY,
        "oracle_head_ok": head_projection == ORACLE_MATERIAL_HEAD_ENC,
        "lane_ctx": f"{lane_ctx:#010x}",
        "material_lane_hint": f"{EXPECTED_MATERIAL_LANE_HINT:#015x}",
        "known_a_share": f"{KNOWN_A_SHARE:#04x}",
    }


def recovered_state23() -> tuple[int, int]:
    s2 = ror64(u64(MATERIAL_80_96, 0), 34)
    s3 = rol64(u64(MATERIAL_80_96, 8), 22)
    return s2, s3


def material0_32_from_s1(s1_value: int) -> bytes:
    s2, s3 = recovered_state23()
    return MATERIAL_0_8 + struct.pack("<Q", s1_value) + struct.pack("<QQ", s2, s3)


def recover_preimage_from_s1(s1_value: int) -> bytes:
    s2, s3 = recovered_state23()
    state = [u64(MATERIAL_0_8, 0), s1_value, s2, s3]
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
    return struct.pack("<4Q", *state)


def encode_oracle_material_head(material: bytes, seeds: bytes, so_key: bytes, a_share: int) -> bytes:
    fb = (a_share ^ so_key[2]) & 0xFF
    out = bytearray(8)
    for i in range(8):
        x = material[i] ^ seeds[(i * 5 + 3) & 0x0F]
        x ^= so_key[(i * 7 + 9) & 0x0F]
        x = (x + ((a_share + ((i * 0x2D + fb) & 0xFF)) & 0xFF)) & 0xFF
        lane = rol8((seeds[(i + 11) & 0x0F] + fb) & 0xFF, i + 1)
        out[i] = x ^ lane
        fb = (out[i] ^ ((material[(i + 3) & 7] + 0x5A + i) & 0xFF)) & 0xFF
    return bytes(out)


def gf_mul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r & 0xFF


def mds32(x: int) -> int:
    a0, a1, a2, a3 = x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF
    b0 = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
    b1 = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
    b2 = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
    b3 = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)
    return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) & 0xFFFFFFFF


def inv_mds32(x: int) -> int:
    a0, a1, a2, a3 = x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF
    b0 = gf_mul(a0, 0x0E) ^ gf_mul(a1, 0x0B) ^ gf_mul(a2, 0x0D) ^ gf_mul(a3, 0x09)
    b1 = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0E) ^ gf_mul(a2, 0x0B) ^ gf_mul(a3, 0x0D)
    b2 = gf_mul(a0, 0x0D) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0E) ^ gf_mul(a3, 0x0B)
    b3 = gf_mul(a0, 0x0B) ^ gf_mul(a1, 0x0D) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0E)
    return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) & 0xFFFFFFFF


def fbox32(x: int, k: int) -> int:
    x = (x ^ k) & 0xFFFFFFFF
    x = (x * 0x45D9F3B) & 0xFFFFFFFF
    x ^= x >> 16
    x = (x * 0x119DE1F3) & 0xFFFFFFFF
    x ^= x >> 15
    return x & 0xFFFFFFFF


def ch32(x: int, y: int, z: int, salt: int) -> int:
    yy = (y ^ ((salt * 0x01010101) & 0xFFFFFFFF)) & 0xFFFFFFFF
    zz = (z ^ rol32(salt, 7)) & 0xFFFFFFFF
    out = ((x & yy) ^ ((~x & 0xFFFFFFFF) & zz)) & 0xFFFFFFFF
    return (out ^ (((salt ^ rol32(x, 3)) * 0x45D9F3B) & 0xFFFFFFFF)) & 0xFFFFFFFF


def maj32(x: int, y: int, z: int, salt: int) -> int:
    a = (x ^ rol32(salt, 11)) & 0xFFFFFFFF
    b = (y ^ ((salt * 0x9E3779B1) & 0xFFFFFFFF)) & 0xFFFFFFFF
    c = (z ^ rol32(salt ^ x, 19)) & 0xFFFFFFFF
    return ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF


def poly32(x: int, y: int, z: int, salt: int) -> int:
    p = ((x ^ rol32(y, 5)) + (((z | 1) * (salt | 1)) & 0xFFFFFFFF)) & 0xFFFFFFFF
    q = ((p & rol32(x, 11)) ^ ((~p & 0xFFFFFFFF) & rol32(y ^ z, 17))) & 0xFFFFFFFF
    q = (q + (((x ^ z) * 0x119DE1F3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return q


def material_project_byte(x: int, lane: int, salt: int) -> int:
    shifted = (x >> ((lane & 3) * 8)) & 0xFFFFFFFF
    carrier = shifted ^ (fbox32(salt ^ shifted, 0x589965CC) & 0xFFFFFF00)
    return carrier & 0xFF


def material_compress_lane32(x: int, y: int, z: int, salt: int, rnd: int) -> int:
    x &= 0xFFFFFFFF
    y &= 0xFFFFFFFF
    z &= 0xFFFFFFFF
    salt &= 0xFFFFFFFF
    lanes = [0, 0, 0, 0]
    carry = (rol32(x, (rnd + 3) & 31) ^ y ^ salt) & 0xFFFFFFFF
    for i in range(4):
        xb = material_project_byte(x, i, salt ^ ((i * 0x45D9F3B) & 0xFFFFFFFF))
        yb = material_project_byte(y, i + 1, salt ^ ((i * 0x119DE1F3) & 0xFFFFFFFF))
        zb = material_project_byte(z, i + 2, salt ^ ((i * 0x9E3779B1) & 0xFFFFFFFF))
        cb = material_project_byte(carry, i, salt ^ ((i * 0x6D2B79F5) & 0xFFFFFFFF))
        sum32 = (xb + (yb ^ cb)) & 0xFFFFFFFF
        diff = ((sum32 & 0xFF) - ((zb + rnd * 0x11 + i) & 0xFF)) & 0xFF
        rc = (xb ^ zb ^ cb ^ (salt & 0xFF) ^ (rnd & 0xFF)) & 7
        rot = rol8(diff, rc)
        gate = ch32(x ^ carry, y ^ rol32(salt, i + 1), z ^ rol32(carry, i + 3), salt ^ 0x27D4EB2F ^ i)
        out_lane = rot ^ material_project_byte(gate, i, salt ^ 0x85EBCA77)
        pos = (i * 3 + rnd) & 3
        lanes[pos] = out_lane
        lane_word = (out_lane << ((pos & 3) * 8)) & 0xFFFFFFFF
        carry = ((carry ^ lane_word) + (sum32 ^ ((zb << (((3 - i) & 3) * 8)) & 0xFFFFFFFF))) & 0xFFFFFFFF
        carry = rol32(carry, (rc + i + 1) & 31)
    packed = lanes[0] | (lanes[1] << 8) | (lanes[2] << 16) | (lanes[3] << 24)
    mixed = mds32((packed ^ salt) & 0xFFFFFFFF)
    mixed ^= rol32(carry, ((x ^ y ^ salt) & 7) + 5)
    return mixed & 0xFFFFFFFF


def derive_lane_context(material: bytes, encoded_head: bytes, seeds: bytes, so_key: bytes, a_share: int) -> int:
    ctx = u32(material, 8) ^ rol32(u32(material, 12), 7)
    ctx ^= u32(seeds, 0) ^ ((a_share * 0x01010101) & 0xFFFFFFFF)
    ctx &= 0xFFFFFFFF
    for i in range(8):
        salt = (0x3A5C742E ^ (i * 0x45D9F3B) ^ rol32(ctx, i + 1)) & 0xFFFFFFFF
        hidden = material[8 + i]
        enc = encoded_head[(i * 5 + 1) & 7]
        seed_lane = seeds[(i * 3 + 2) & 0x0F]
        key_lane = so_key[(i * 7 + 4) & 0x0F]
        ctx_lane = (ctx >> ((i & 3) * 8)) & 0xFF
        braid = hidden ^ enc
        braid = (braid - (seed_lane ^ key_lane)) & 0xFF
        braid = (braid + (ctx_lane ^ a_share)) & 0xFF
        rc = (braid ^ hidden ^ seed_lane ^ ctx_lane) & 7
        braid = rol8(braid, rc)
        fold = material_compress_lane32(u32(material, 8), u32(material, 0), u32(seeds, (i & 3) * 4), salt ^ braid, i + 1)
        lane_word = (braid << ((i & 3) * 8)) & 0xFFFFFFFF
        ctx = ((ctx ^ lane_word) + (fold ^ ((enc * 0x01010101) & 0xFFFFFFFF))) & 0xFFFFFFFF
        ctx = rol32(ctx, (rc + i + 5) & 31)
    tail = material_compress_lane32(u32(material, 12), u32(seeds, 4), u32(so_key, 0), ctx ^ 0xB492B66F, 9)
    return (ctx ^ tail) & 0xFFFFFFFF


def derive_material_mid_tag(material: bytes, seeds: bytes, so_key: bytes, a_share: int, lane_ctx: int) -> int:
    a = u32(material, 8) ^ (u32(so_key, 0) ^ rol32(lane_ctx, 5))
    b = u32(material, 12) ^ (u32(so_key, 4) ^ rol32(lane_ctx, 13))
    c = u32(material, 0) ^ (u32(seeds, 8) ^ lane_ctx)
    d = u32(material, 4) ^ (u32(seeds, 12) ^ rol32(lane_ctx, 21))
    lane_ctx &= 0xFFFFFFFF
    for r in range(5):
        sw = u32(seeds, (r & 3) * 4)
        salt = (0x7E3A19C5 ^ (r * 0x45D9F3B) ^ (a_share * 0x01010101) ^ rol32(lane_ctx, r + 3)) & 0xFFFFFFFF
        lane = material_compress_lane32(a ^ sw, b, c ^ d, salt, r)
        ch = ch32(a ^ sw, b, c, salt ^ 0xD6E8FEB8)
        maj = maj32(a, c ^ sw, d, salt ^ 0xC2B2AE35)
        poly = poly32(b ^ sw, (c + salt + lane) & 0xFFFFFFFF, d ^ a_share, salt ^ 0x165667B1)
        f = fbox32((b ^ ch ^ lane ^ rol32(c ^ maj, r + 3)) & 0xFFFFFFFF, (sw ^ poly ^ d ^ rol32(lane, r + 1)) & 0xFFFFFFFF)
        g = mds32(a ^ maj ^ f ^ poly ^ lane)
        feed = (((a ^ lane) & rol32(b, r + 5)) ^ ((~b & 0xFFFFFFFF) & rol32(c ^ d ^ ch ^ lane, r + 1))) & 0xFFFFFFFF
        a = rol32(((a ^ lane) + (g ^ feed)) & 0xFFFFFFFF, 5 + ((r ^ lane) & 7))
        b = rol32((b + (((a * (0x9E3779B1 + r * 2)) & 0xFFFFFFFF) ^ lane)) & 0xFFFFFFFF, 11 + ((r + (lane >> 3)) & 15))
        b ^= inv_mds32(g) ^ ch ^ material_compress_lane32(lane, c, d, salt ^ g, r + 3)
        b &= 0xFFFFFFFF
        c = ((c ^ rol32(a ^ poly ^ lane, r + 7)) + (b ^ sw ^ maj)) & 0xFFFFFFFF
        d = rol32((d + (c ^ ch ^ ((a ^ lane) >> ((r & 7) + 1)))) & 0xFFFFFFFF, 3 + ((r * 5 + (lane & 7)) & 15))
        lane_ctx = ((lane_ctx ^ lane) + material_compress_lane32(a, b ^ c, d, salt ^ lane, r + 7)) & 0xFFFFFFFF
    x = (a ^ rol32(b, 13)) & 0xFFFFFFFF
    x = (x + (c ^ rol32(d, 19))) & 0xFFFFFFFF
    x ^= ((a_share * 0x01020408) & 0xFFFFFFFF) ^ lane_ctx
    return x & 0xFFFFFFFF


def derive_fake_syndrome(material: bytes, a_share: int, lane_ctx: int) -> int:
    cx_key = compute_const_xor_key()
    hint_enc = bytes([
        0xB2, 0x71, 0x0E, 0x5D, 0x93, 0x42, 0xC8, 0x1F,
        0x2A, 0xE4, 0x77, 0x90, 0x5C, 0x39, 0xA6, 0xD1,
    ])
    hint = bytearray(hint_enc[i] ^ cx_key[i & 0x0F] for i in range(16))
    ctx = lane_ctx
    for i in range(16):
        ctx_byte = (ctx >> ((i & 3) * 8)) & 0xFF
        hint[i] ^= ((a_share ^ ctx_byte) + i * 0x2B) & 0xFF

    syndrome = ((a_share + 0x6D) & 0xFF) ^ (material[7] ^ (ctx & 0xFF))
    for i in range(16):
        lane = material[8 + ((i * 5 + 3) & 0x0F)]
        d = lane ^ hint[i]
        d ^= rol8(material[16 + ((i * 3 + 1) & 0x0F)], i + 1)
        d ^= (ctx >> (((i + 1) & 3) * 8)) & 0xFF
        syndrome = (syndrome + ((d + i * 0x17) & 0xFF)) & 0xFF
        syndrome = rol8(syndrome, (i & 3) + 1)
        mix = (d * 0x3D + i) & 0xFF
        syndrome ^= mix
        ctx = (ctx ^ (mix << ((i & 3) * 8))) & 0xFFFFFFFF
        ctx = (ctx + ((d * 0x01010101) & 0xFFFFFFFF)) & 0xFFFFFFFF
        ctx = rol32(ctx, (mix & 7) + 3)
    return syndrome & 0xFF


def _parse_bv_value(value: object) -> int:
    text = str(value)
    if text.startswith("#b"):
        return int(text[2:], 2)
    if text.startswith("#x"):
        return int(text[2:], 16)
    return int(text, 0)


class PaddingModel:
    name: str
    detail: str = ""

    def check(self) -> str:
        raise NotImplementedError

    def value(self) -> int:
        raise NotImplementedError

    def block_value(self, value: int) -> None:
        raise NotImplementedError

    def reason_unknown(self) -> str:
        return "unknown"


def build_padding_model_bitwuzla(
    timeout_ms: int,
    lane_hint_constraints_: list[tuple[int, int, int, int, int, int, int, int, int]] | None = None,
) -> PaddingModel:
    try:
        from bitwuzla import Bitwuzla, Kind, Option, Options, Result, TermManager
    except ImportError as exc:
        raise RuntimeError("需要安装 bitwuzla Python 绑定") from exc

    tm = TermManager()
    bv64_sort = tm.mk_bv_sort(64)
    bv8_sort = tm.mk_bv_sort(8)
    bv1_sort = tm.mk_bv_sort(1)

    def bv64(v: int):
        return tm.mk_bv_value(bv64_sort, v & MASK64)

    def bv8(v: int):
        return tm.mk_bv_value(bv8_sort, v & 0xFF)

    def bv1(v: int):
        return tm.mk_bv_value(bv1_sort, v & 1)

    def bxor(a, b):
        return tm.mk_term(Kind.BV_XOR, [a, b])

    def bsub(a, b):
        return tm.mk_term(Kind.BV_SUB, [a, b])

    def beq(a, b):
        return tm.mk_term(Kind.EQUAL, [a, b])

    def bnot(a):
        return tm.mk_term(Kind.NOT, [a])

    def brol64(x, n: int):
        n &= 63
        return x if n == 0 else tm.mk_term(Kind.BV_ROLI, [x], [n])

    def bror64(x, n: int):
        n &= 63
        return x if n == 0 else tm.mk_term(Kind.BV_RORI, [x], [n])

    # 这是预期的逆向后模型：native MBA 外壳已被化简，
    # 但核心难点仍留在 SMT 中：
    # 1. 反演 12 轮 64 位 ARX material 扩展器；
    # 2. 满足 46 条已恢复的单 bit Q46 lane 约束。
    s2, s3 = recovered_state23()
    s1 = tm.mk_const(bv64_sort, "material_8_16")
    state = [bv64(u64(MATERIAL_0_8, 0)), s1, bv64(s2), bv64(s3)]
    for r in range(11, -1, -1):
        e0, e1, e2, e3 = state
        d3 = e3
        d1 = e1
        d0 = bxor(e0, e3)
        d2 = bxor(e2, e1)
        c3 = bror64(bxor(d3, d2), 3)
        c2 = brol64(bsub(bxor(d2, bv64(r + 4)), c3), 8)
        c1 = bror64(bxor(d1, d0), 3)
        c0 = brol64(bsub(bxor(d0, bv64(r)), c1), 8)
        state = [c0, c1, c2, c3]

    opts = Options()
    opts.set(Option.PRODUCE_MODELS, True)
    opts.set(Option.TIME_LIMIT_PER, timeout_ms)
    solver = Bitwuzla(tm, opts)

    def bit(pos: int):
        return tm.mk_term(Kind.BV_EXTRACT, [s1], [pos, pos])

    for p0, p1, p2, p3, p4, a_const, b_const, c_const, expected in lane_hint_constraints_ or []:
        # 单个 lane bit 的已还原 Q46 形式：
        #   (bit[p0] ^ bit[p1] ^ a_const) ^
        #   ((bit[p2] ^ b_const) & (bit[p3] ^ bit[p4] ^ c_const))
        a = bxor(bxor(bit(p0), bit(p1)), bv1(a_const))
        b = bxor(bit(p2), bv1(b_const))
        c = bxor(bxor(bit(p3), bit(p4)), bv1(c_const))
        solver.assert_formula(beq(bxor(a, tm.mk_term(Kind.BV_AND, [b, c])), bv1(expected)))

    for i in range(25, 32):
        word = state[i // 8]
        lo = (i & 7) * 8
        byte = tm.mk_term(Kind.BV_EXTRACT, [word], [lo + 7, lo])
        solver.assert_formula(beq(byte, bv8(0x5A)))

    class BitwuzlaPaddingModel(PaddingModel):
        name = "bitwuzla"

        def check(self) -> str:
            result = solver.check_sat()
            if result == Result.SAT:
                return "sat"
            if result == Result.UNKNOWN:
                return "unknown"
            return "unsat"

        def value(self) -> int:
            return _parse_bv_value(solver.get_value(s1)) & MASK64

        def block_value(self, value: int) -> None:
            solver.assert_formula(bnot(beq(s1, bv64(value))))

        def reason_unknown(self) -> str:
            return "超时或后端状态未知"

    return BitwuzlaPaddingModel()

def solve_material_lane(timeout_ms: int, max_candidates: int, so_key: bytes, verbose: bool) -> tuple[int, int, int, str]:
    lane_ctx = derive_lane_context_from_oracle_tag(so_key)
    if encode_oracle_material_head(MATERIAL_0_8 + b"\x00" * 8, MATERIAL_80_96, so_key, KNOWN_A_SHARE) != ORACLE_MATERIAL_HEAD_ENC:
        raise RuntimeError("oracle material-head 投影与 APK 常量不匹配")

    lane_hint_constraints_ = material_lane_hint_constraints(so_key, lane_ctx)
    solver = build_padding_model_bitwuzla(timeout_ms, lane_hint_constraints_)
    candidates = 0
    start = time.time()
    if verbose:
        print(
            f"[smt] backend={solver.name} timeout_ms={timeout_ms} "
            f"max_candidates={max_candidates} q46_constraints={len(lane_hint_constraints_)}",
            file=sys.stderr,
            flush=True,
        )
        detail = getattr(solver, "detail", "")
        if detail:
            print(f"[smt] {detail}", file=sys.stderr, flush=True)
    while candidates < max_candidates:
        if verbose:
            print(f"[smt] check candidate {candidates + 1}", file=sys.stderr, flush=True)
        result = solver.check()
        if result == "unknown":
            reason = solver.reason_unknown()
            raise RuntimeError(f"SMT 求解器在枚举第 {candidates + 1} 个候选前返回 unknown：{reason}")
        if result != "sat":
            break
        s1_value = solver.value()
        candidates += 1
        material = material0_32_from_s1(s1_value)
        preimage = recover_preimage_from_s1(s1_value)
        if verbose:
            print(f"[smt] candidate {candidates}: material[8:16]={s1_value.to_bytes(8, 'little').hex()}", file=sys.stderr, flush=True)

        # 大块 ARX 逆向和 Q46 lane-hint 约束保留在 Bitwuzla 中。
        # 剩余公开 native 检查对每个候选做 Python 计算更便宜，
        # 没必要继续内联成更大的 BV 公式。
        if preimage[25:] != b"\x5A" * 7:
            solver.block_value(s1_value)
            continue
        if ((ror64(rol64(u64(MATERIAL_80_96, 8), 22), 11) >> 32) & 0xFFFFFFFF) != u32(MATERIAL_60_64, 0):
            solver.block_value(s1_value)
            continue
        derived_ctx = derive_lane_context(material[:16], ORACLE_MATERIAL_HEAD_ENC, MATERIAL_80_96, so_key, KNOWN_A_SHARE)
        if derived_ctx != lane_ctx:
            solver.block_value(s1_value)
            continue
        mid_tag = derive_material_mid_tag(material[:16], MATERIAL_80_96, so_key, KNOWN_A_SHARE, lane_ctx)
        if mid_tag != EXPECTED_MATERIAL_MID_TAG:
            solver.block_value(s1_value)
            continue
        fake = derive_fake_syndrome(material, KNOWN_A_SHARE, lane_ctx)
        if fake != EXPECTED_FAKE_SYNDROME:
            solver.block_value(s1_value)
            continue
        return s1_value, candidates, int(time.time() - start), solver.name

    raise RuntimeError(f"枚举 {candidates} 个 SMT 候选后，没有 material[8:16] 候选通过过滤")


def main() -> int:
    parser = argparse.ArgumentParser(description="KCTF2026 Bitwuzla material[8:16] 求解器")
    parser.add_argument("apk", nargs="?", type=Path, default=DEFAULT_APK)
    parser.add_argument("--self-test", action="store_true", help="校验公开 APK 约束并退出，不运行 SMT")
    parser.add_argument("--timeout-ms", type=int, default=600_000, help="每次候选检查的 Bitwuzla 超时时间")
    parser.add_argument("--max-candidates", type=int, default=4096, help="最多枚举的填充候选数量")
    parser.add_argument("--verbose", action="store_true", help="将求解进度打印到 stderr")
    args = parser.parse_args()

    digest = apk_sha256(args.apk)
    so = read_apk_so(args.apk)
    so_key, crc = derive_sokey(so)
    lane_ctx = derive_lane_context_from_oracle_tag(so_key)
    if args.self_test:
        for key, value in public_constraint_selftest(so_key, crc, digest).items():
            print(f"{key}={value}")
        return 0

    value, checked, elapsed, solver_name = solve_material_lane(args.timeout_ms, args.max_candidates, so_key, args.verbose)
    material_8_16 = value.to_bytes(8, "little")

    print(f"apk={args.apk}")
    print(f"apk_sha256={digest}")
    print(f"guard_crc32={crc:08x}")
    print(f"soKey={so_key.hex()}")
    print("data_sources=apk .kctfguard, encoded oracle blob, oracle tag, native material checks")
    print(f"material[0:8]={MATERIAL_0_8.hex()}")
    print(f"material[8:16]={material_8_16.hex()}")
    print(f"material[60:64]={MATERIAL_60_64.hex()}")
    print(f"material[80:96]={MATERIAL_80_96.hex()}")
    print(f"oracle_material_head_enc={ORACLE_MATERIAL_HEAD_ENC.hex()}")
    print(f"oracle_tag={ORACLE_TAG.hex()}")
    print(f"lane_ctx={lane_ctx:#010x}")
    print(f"material_mid_tag={EXPECTED_MATERIAL_MID_TAG:#010x}")
    print(f"material_lane_hint={EXPECTED_MATERIAL_LANE_HINT:#015x}")
    print(f"fake_syndrome={EXPECTED_FAKE_SYNDROME:#04x}")
    print(f"known_a_share={KNOWN_A_SHARE:#04x}")
    print(f"smt_solver={solver_name}")
    print(f"smt_padding_candidates_checked={checked}")
    print(f"elapsed_seconds={elapsed}")
    # 本地 pybitwuzla 绑定在产生有效模型后析构大型 BV 项时可能触发段错误。
    # 这里输出已经完整，因此直接退出进程。
    sys.stdout.flush()
    sys.stderr.flush()
    import os
    os._exit(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
