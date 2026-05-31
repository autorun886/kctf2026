#!/usr/bin/env python3
"""
precompute_b.py — 方案 B 预计算脚本
选定 flag，正向模拟完整 pipeline，输出：
  - ENC_EXPECTED_STATE（填入 jni_entry.c）
  - EXPECTED_SOKEY_CHECK（填入 key_expand.c）
  - IV（填入 jni_entry.c）

用法：py -3 precompute_b.py <libkctf.so路径>
"""
import struct, sys, zlib

SO_PATH = sys.argv[1] if len(sys.argv) > 1 else \
    "app/build/intermediates/cxx/Debug/162k275h/obj/arm64-v8a/libkctf.so"

# ── soKey 派生（只读 .text section，与更新后的 deriveNativeKey 一致）──
def derive_sokey(so_path):
    with open(so_path, "rb") as f:
        data = f.read()
    e_shoff     = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum     = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx  = struct.unpack_from('<H', data, 62)[0]
    sh = data[e_shoff + e_shstrndx*e_shentsize : e_shoff + (e_shstrndx+1)*e_shentsize]
    strtab_off  = struct.unpack_from('<Q', sh, 24)[0]
    strtab_size = struct.unpack_from('<Q', sh, 32)[0]
    strtab = data[strtab_off : strtab_off + strtab_size]
    text_bytes = None
    for i in range(e_shnum):
        sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
        name_idx = struct.unpack_from('<I', sh, 0)[0]
        end = strtab.index(b'\x00', name_idx)
        name = strtab[name_idx:end].decode()
        if name == '.text':
            off  = struct.unpack_from('<Q', sh, 24)[0]
            size = struct.unpack_from('<Q', sh, 32)[0]
            text_bytes = data[off : off + size]
            break
    assert text_bytes is not None
    crc = zlib.crc32(text_bytes) & 0xFFFFFFFF
    EXPAND = [0xA3F1B28C7D4E5F60, 0x9C8B7A6D5E4F3021,
              0x1F2E3D4C5B6A7980, 0xD0E1F2038495A6B7]
    MUL, ADD, M64 = 0x5851F42D4C957F2D, 0x14057B7EF767814F, (1<<64)-1
    key = bytearray(16)
    for i in range(4):
        m = ((crc ^ EXPAND[i]) * MUL + ADD) & M64
        key[i*4]   = (m >> 24) & 0xFF
        key[i*4+1] = (m >> 16) & 0xFF
        key[i*4+2] = (m >>  8) & 0xFF
        key[i*4+3] = m & 0xFF
    return bytes(key), crc

soKey, crc = derive_sokey(SO_PATH)
print(f"CRC32: {crc:08x}")
print(f"soKey: {soKey.hex()}")

# ── 选定 flag（25 字节随机值，不可猜测格式）────────────────
FLAG_B = bytes([
    0x7A, 0xE3, 0x1B, 0x94, 0xD2, 0x56, 0xF8, 0x0C,
    0x41, 0xB7, 0x29, 0x8E, 0x63, 0xA5, 0xDF, 0x10,
    0x4B, 0xC8, 0x72, 0x3D, 0x96, 0x0F, 0xE4, 0x58, 0xAD
])
flag = FLAG_B
assert len(flag) == 25
print(f"\nflag (hex): {flag.hex()}")
import base64
print(f"flag (b64): {base64.b64encode(flag).decode()}")

# ── expand_key_material（ARX 12 轮 + squeeze）────────────
def ror64(x, n): return ((x >> n) | (x << (64 - n))) & ((1<<64)-1)
def rol64(x, n): return ((x << n) | (x >> (64 - n))) & ((1<<64)-1)

def expand_key_material(flag_bytes, out_len=96):
    buf = bytearray(32)
    buf[:25] = flag_bytes
    buf[25:] = bytes([0x5A] * 7)
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(16):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1<<64)-1)
        s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1<<64)-1)
        s[2] ^= (r + 4)
        s[3] = rol64(s[3], 3) ^ s[2]
        s[0] ^= s[3]
        s[2] ^= s[1]
    out = bytearray()
    while len(out) < out_len:
        chunk = min(32, out_len - len(out))
        out += struct.pack('<4Q', *s)[:chunk]
        s[0] = (s[0] + s[2]) & ((1<<64)-1)
        s[1] ^= s[3]
        s[2] = rol64(s[2], 17)
        s[3] = ror64(s[3], 11)
    return bytes(out)

# ── key_schedule ──────────────────────────────────────────
material = bytearray(128)
material[:96] = expand_key_material(flag)
# soKey 混入 [96:112]
for i in range(16):
    material[96 + i] = material[i] ^ soKey[i]
# IPC 全零（ipc_verify.c 返回全零）
for i in range(16):
    material[112 + i] = material[32 + i] ^ 0

round_keys = [struct.unpack_from('<I', material, i*4)[0] for i in range(16)]
configs = []
for i in range(16):
    b = material[64 + i]
    configs.append({
        'sbox_selector':  (b >> 0) & 0x03,
        'shift_pattern':  (b >> 2) & 0x03,
        'mix_matrix_idx': (b >> 4) & 0x03,
        'nonlinear_mode': (b >> 6) & 0x03,
    })
sbox_seeds = [struct.unpack_from('<I', material, 80 + i*4)[0] for i in range(4)]
delta = struct.unpack_from('<I', material, 96)[0]

# EXPECTED_SOKEY_CHECK = round_keys[15] ^ soKey[12:16]
sokey_12_16 = struct.unpack_from('<I', soKey, 12)[0]
EXPECTED_SOKEY_CHECK = round_keys[15] ^ sokey_12_16
print(f"\nEXPECTED_SOKEY_CHECK: {EXPECTED_SOKEY_CHECK:#010x}")
print(f"delta: {delta:#010x}")

# ── generate_sbox（Fisher-Yates + xorshift32）────────────
def generate_sbox(seed):
    sbox = list(range(256))
    xs = seed & 0xFFFFFFFF
    for i in range(255, 0, -1):
        xs ^= (xs << 13) & 0xFFFFFFFF
        xs ^= (xs >> 17) & 0xFFFFFFFF
        xs ^= (xs << 5)  & 0xFFFFFFFF
        j = xs % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox

sboxes = [generate_sbox(s) for s in sbox_seeds]
print(f"sbox_seeds: {[hex(s) for s in sbox_seeds]}")

# ── GF(2^8) 运算 ──────────────────────────────────────────
def gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return r

def gf_pow(base, exp):
    result = 1
    while exp > 0:
        if exp & 1: result = gf_mul(result, base)
        base = gf_mul(base, base)
        exp >>= 1
    return result

# ── MDS 矩阵 ─────────────────────────────────────────────
MDS = [
    [[0x02,0x03,0x01,0x01],[0x01,0x02,0x03,0x01],
     [0x01,0x01,0x02,0x03],[0x03,0x01,0x01,0x02]],
    [[0x05,0x03,0x04,0x02],[0x02,0x05,0x03,0x04],
     [0x04,0x02,0x05,0x03],[0x03,0x04,0x02,0x05]],
    [[0x07,0x06,0x02,0x03],[0x03,0x07,0x06,0x02],
     [0x02,0x03,0x07,0x06],[0x06,0x02,0x03,0x07]],
    [[0x09,0x0E,0x05,0x04],[0x04,0x09,0x0E,0x05],
     [0x05,0x04,0x09,0x0E],[0x0E,0x05,0x04,0x09]],
]

SHIFTS = [
    [0,1,2,3], [0,1,3,4], [0,2,3,1], [0,3,1,2]
]

NL_POWER = [7, 11, 13, 23]

# ── SPN 单轮 ─────────────────────────────────────────────
def apply_sbox(state, sel):
    return [sboxes[sel][b] for b in state]

def shift_rows(state, shifts):
    tmp = state[:]
    result = [0] * 16
    for row in range(4):
        s = shifts[row] & 0x03
        for col in range(4):
            result[row + 4 * col] = tmp[row + 4 * ((col + s) % 4)]
    return result

def mix_columns_mds(state, matrix):
    result = [0] * 16
    for col in range(4):
        inp = state[col*4 : col*4+4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= gf_mul(matrix[i][j], inp[j])
            result[col*4 + i] = v
    return result

def nonlinear_feedback(state, mode, delta_val, rnd):
    power = NL_POWER[mode & 0x03]
    round_const = (delta_val >> ((rnd % 4) * 8)) & 0xFF
    return [gf_pow(b ^ round_const ^ (rnd & 0xFF), power) for b in state]

def add_round_key(state, round_key):
    k = struct.pack('<I', round_key)
    return [state[i] ^ k[i % 4] for i in range(16)]

def spn_round(state, cfg, round_key, delta_val, rnd):
    # S-Box 选择：前 8 轮静态，后 8 轮依赖 state[0]
    if rnd < 8:
        sel = cfg['sbox_selector']
    else:
        sel = (cfg['sbox_selector'] ^ state[0]) & 0x03
    state = apply_sbox(state, sel)
    state = shift_rows(state, SHIFTS[cfg['shift_pattern']])
    state = mix_columns_mds(state, MDS[cfg['mix_matrix_idx']])
    state = nonlinear_feedback(state, cfg['nonlinear_mode'], delta_val, rnd)
    state = add_round_key(state, round_key)
    return state

def _crc32_16(data):
    T = [0x00000000,0x1DB71064,0x3B6E20C8,0x26D930AC,
         0x76DC4190,0x6B6B51F4,0x4DB26158,0x5005713C,
         0xEDB88320,0xF00F9344,0xD6D6A3E8,0xCB61B38C,
         0x9B64C2B0,0x86D3D2D4,0xA00AE278,0xBDBDF21C]
    crc = 0xFFFFFFFF
    for b in data[:16]:
        crc ^= b
        crc = ((crc >> 4) ^ T[crc & 0x0F]) & 0xFFFFFFFF
        crc = ((crc >> 4) ^ T[crc & 0x0F]) & 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF

def spn_encrypt(state, round_keys, configs, delta_val):
    state_crc_mix = 0
    for rnd in range(16):
        if rnd == 8:
            state_crc_mix = _crc32_16(bytes(state))
        dyn_key = round_keys[rnd]
        if rnd >= 8:
            state_u32 = struct.unpack_from('<I', bytes(state[:4]))[0]
            dyn_key ^= state_u32
            dyn_key ^= state_crc_mix
        state = spn_round(state, configs[rnd], dyn_key, delta_val, rnd)
    return state

# ── 选定 IV 并加密 ────────────────────────────────────────
IV = [0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
      0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10]

state = IV[:]
state = spn_encrypt(state, round_keys, configs, delta)
final_state = bytes(state)
print(f"\nIV:          {bytes(IV).hex()}")
print(f"final_state: {final_state.hex()}")

# ENC_EXPECTED_STATE = final_state XOR soKey
enc = bytes(final_state[i] ^ soKey[i] for i in range(16))
print(f"ENC_EXPECTED_STATE: {enc.hex()}")

# ── 输出 C 代码 ───────────────────────────────────────────
def c_array(name, data, typ="uint8_t"):
    vals = ', '.join(f'0x{b:02X}' for b in data)
    return f"static const {typ} {name}[{len(data)}] = {{{vals}}};"

def c_u32(name, val):
    return f"#define {name} {val:#010x}u"

print(f"\n// ── 填入 jni_entry.c ──")
print(c_array("IV", IV))
print(c_array("ENC_EXPECTED_STATE", enc))

print(f"\n// ── 填入 key_expand.c ──")
print(c_u32("EXPECTED_SOKEY_CHECK", EXPECTED_SOKEY_CHECK))

print(f"\n// ── 验证用（正向模拟结果）──")
print(f"// flag (b64): {base64.b64encode(flag).decode()}")
print(f"// soKey:      {soKey.hex()}")
