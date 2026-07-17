#!/usr/bin/env python3
"""
verify.py — 端到端验证脚本
验证方案 A 和方案 B 的 flag 正确性：
  1. 正确 flag → final_state == expected（应通过）
  2. 错误 flag → final_state != expected（应失败）
  3. soKey 错误 → delta 被污染 → 失败（方案 B）

用法：py -3 verify.py <libkctf.so路径>
"""
import struct, sys, zlib, base64

SO_PATH = sys.argv[1] if len(sys.argv) > 1 else \
    "app/build/intermediates/cxx/Debug/162k275h/obj/arm64-v8a/libkctf.so"

# ── soKey 派生 ────────────────────────────────────────────
def derive_sokey(so_path):
    """只读 .text section（与更新后的 deriveNativeKey 一致）"""
    with open(so_path, "rb") as f: data = f.read()
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
        if strtab[name_idx:end] == b'.text':
            off  = struct.unpack_from('<Q', sh, 24)[0]
            size = struct.unpack_from('<Q', sh, 32)[0]
            text_bytes = data[off : off + size]
            break
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
    return bytes(key)

soKey = derive_sokey(SO_PATH)

# ════════════════════════════════════════════════════════════
# 方案 B 验证
# ════════════════════════════════════════════════════════════
print("=" * 50)
print("方案 B 验证")
print("=" * 50)

FLAG_B = bytes([
    0x7A, 0xE3, 0x1B, 0x94, 0xD2, 0x56, 0xF8, 0x0C,
    0x41, 0xB7, 0x29, 0x8E, 0x63, 0xA5, 0xDF, 0x10,
    0x4B, 0xC8, 0x72, 0x3D, 0x96, 0x0F, 0xE4, 0x58, 0xAD
])
IV_B   = bytes([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10])
ENC_B  = bytes([0xd1,0x90,0xfd,0x31,0xee,0xe3,0x9d,0x2c,0x40,0x6f,0x37,0xeb,0x03,0xb8,0x9a,0x0f])
EXPECTED_SOKEY_CHECK = 0x7af90072

def ror64(x, n): return ((x >> n) | (x << (64 - n))) & ((1<<64)-1)
def rol64(x, n): return ((x << n) | (x >> (64 - n))) & ((1<<64)-1)

def expand_key_material(flag_bytes):
    buf = bytearray(32)
    buf[:25] = flag_bytes
    buf[25:] = bytes([0x5A] * 7)
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(12):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1<<64)-1); s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1<<64)-1); s[2] ^= (r + 4)
        s[3] = rol64(s[3], 3) ^ s[2]
        s[0] ^= s[3]; s[2] ^= s[1]
    out = bytearray()
    while len(out) < 96:
        chunk = min(32, 96 - len(out))
        out += struct.pack('<4Q', *s)[:chunk]
        s[0] = (s[0] + s[2]) & ((1<<64)-1); s[1] ^= s[3]
        s[2] = rol64(s[2], 17); s[3] = ror64(s[3], 11)
    return bytes(out)

def const_xor_key():
    kpt_raw = struct.pack('<6I', 0x00000001, 0x00000002, 0xdeadbeef, 0xcafebabe,
                          0x12345678, 0x9abcdef0)
    piece0 = zlib.crc32(kpt_raw) & 0xFFFFFFFF
    iv_a2 = 0x8BADF00D
    piece1 = 0xDEADBEEF ^ (((iv_a2 >> 13) | (iv_a2 << 19)) & 0xFFFFFFFF)
    piece2 = 0x67452301 ^ 0x3CC35AA5
    seed = piece0 ^ piece1 ^ piece2
    key = bytearray(16)
    s = seed
    for i in range(4):
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
        struct.pack_into('<I', key, i * 4, s)
    return bytes(key)

def ipc_material():
    key = const_xor_key()
    return bytes(key[(i * 5 + 3) & 0x0F] ^ ((0xC3 + i * 0x29) & 0xFF)
                 for i in range(16))

def key_schedule_b(flag, so_key, expected_check):
    mat = bytearray(128)
    mat[:96] = expand_key_material(flag)
    for i in range(16): mat[96+i] = mat[i] ^ so_key[i]
    ipc = ipc_material()
    for i in range(16): mat[112+i] = mat[32+i] ^ ipc[i]
    rk = [struct.unpack_from('<I', mat, i*4)[0] ^
          struct.unpack_from('<I', mat, 112 + ((i & 3) * 4))[0]
          for i in range(16)]
    cfgs = []
    for i in range(16):
        b = mat[64+i]
        cfgs.append({'ss':(b>>0)&3,'sp':(b>>2)&3,'mm':(b>>4)&3,'nm':(b>>6)&3})
    seeds = [struct.unpack_from('<I', mat, 80+i*4)[0] for i in range(4)]
    delta = struct.unpack_from('<I', mat, 96)[0] ^ struct.unpack_from('<I', mat, 112)[0]
    # soKey 双向验证
    check = rk[15] ^ struct.unpack_from('<I', so_key, 12)[0]
    diff  = check ^ expected_check
    poison = (((diff | ((~diff + 1) & 0xFFFFFFFF)) >> 31) & 1) * 0xDEADBEEF
    delta ^= poison
    return rk, cfgs, seeds, delta

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

def gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        hi = a & 0x80; a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return r

def gf_pow(base, exp):
    r = 1
    while exp:
        if exp & 1: r = gf_mul(r, base)
        base = gf_mul(base, base); exp >>= 1
    return r

MDS = [
    [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]],
    [[5,3,4,2],[2,5,3,4],[4,2,5,3],[3,4,2,5]],
    [[7,6,2,3],[3,7,6,2],[2,3,7,6],[6,2,3,7]],
    [[9,14,5,4],[4,9,14,5],[5,4,9,14],[14,5,4,9]],
]
SHIFTS = [[0,1,2,3],[0,1,3,4],[0,2,3,1],[0,3,1,2]]
NL_POWER = [7,11,13,23]

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

def spn_encrypt_b(state, rk, cfgs, sboxes, delta):
    state = list(state)
    state_crc_mix = 0
    for rnd in range(16):
        if rnd == 8:
            state_crc_mix = _crc32_16(bytes(state))
        dyn_key = rk[rnd]
        if rnd >= 8:
            dyn_key ^= struct.unpack_from('<I', bytes(state[:4]))[0]
            dyn_key ^= state_crc_mix
        sel = cfgs[rnd]['ss'] if rnd < 8 else (cfgs[rnd]['ss'] ^ state[0]) & 3
        state = [sboxes[sel][b] for b in state]
        tmp = state[:]
        for row in range(4):
            s = SHIFTS[cfgs[rnd]['sp']][row] & 3
            for col in range(4):
                state[row + 4*col] = tmp[row + 4*((col+s)%4)]
        res = [0]*16
        for col in range(4):
            inp = state[col*4:col*4+4]
            m = MDS[cfgs[rnd]['mm']]
            for i in range(4):
                v = 0
                for j in range(4): v ^= gf_mul(m[i][j], inp[j])
                res[col*4+i] = v
        state = res
        power = NL_POWER[cfgs[rnd]['nm'] & 3]
        rc = (delta >> ((rnd % 4) * 8)) & 0xFF
        state = [gf_pow(b ^ rc ^ (rnd & 0xFF), power) for b in state]
        k = struct.pack('<I', dyn_key)
        state = [state[i] ^ k[i%4] for i in range(16)]
    return bytes(state)

def verify_b(flag, so_key, iv, enc_expected, check_const, label):
    rk, cfgs, seeds, delta = key_schedule_b(flag, so_key, check_const)
    sboxes = [generate_sbox(s) for s in seeds]
    final = spn_encrypt_b(list(iv), rk, cfgs, sboxes, delta)
    expected = bytes(enc_expected[i] ^ so_key[i] for i in range(16))
    ok = final == expected
    print(f"  {label}: {'PASS' if ok else 'FAIL'}  final={final.hex()[:16]}...")
    return ok

print(f"soKey: {soKey.hex()}")
r1 = verify_b(FLAG_B, soKey, IV_B, ENC_B, EXPECTED_SOKEY_CHECK, "正确 flag")
r2 = verify_b(b'\x00'*25, soKey, IV_B, ENC_B, EXPECTED_SOKEY_CHECK, "错误 flag (全零)")
r3 = verify_b(FLAG_B, b'\x00'*16, IV_B, ENC_B, EXPECTED_SOKEY_CHECK, "错误 soKey (全零)")
assert r1 and not r2 and not r3, "方案 B 验证失败"
print("方案 B: 全部通过\n")

# ════════════════════════════════════════════════════════════
# 方案 A 验证（模拟修复链 + core_compute）
# ════════════════════════════════════════════════════════════
print("=" * 50)
print("方案 A 验证")
print("=" * 50)

FLAG_A = base64.b64decode("AgAAAAGDLb0FxwVz5bl5N57ewK3eB0ITNw==")
ENC_A  = bytes([0xf9,0x4b,0xe8,0x07,0x9c,0xcc,0x29,0x74,0x6d,0xee,0x4c,0x44,0x26,0x01,0x4d,0x09])

# 从 precompute_a.py 的逻辑重建
BB6_ADR_OFF = 0x39b8  # Release build
XTEA_DELTA  = 0x9E3779B9
LCG_SEED    = 0xDEADC0DE

def lcg_expand(seed, sbox_first=0):
    lcg = (seed ^ (sbox_first * 0x01010101)) & 0xFFFFFFFF
    rc = []
    for _ in range(32):
        lcg = (lcg * 1664525 + 1013904223) & 0xFFFFFFFF
        rc.append(lcg)
    return rc

def xorshift32_stream(seed, n):
    xs = seed & 0xFFFFFFFF
    out = []
    for _ in range(n):
        xs ^= (xs << 13) & 0xFFFFFFFF
        xs ^= (xs >> 17) & 0xFFFFFFFF
        xs ^= (xs << 5)  & 0xFFFFFFFF
        out.append(xs & 0xFF)
    return out

def verify_a(flag, so_key, enc_expected, label):
    # repair_sbox
    sbox_seed = struct.unpack_from('<I', flag, 9)[0]
    cfg_dep   = BB6_ADR_OFF & 0xFF  # 0xA4 → 164
    ks = xorshift32_stream(sbox_seed, 256)
    sbox = [0] * 256
    for i in range(256):
        sbox[(i + cfg_dep) & 0xFF] ^= ks[i]
    sbox_first = sbox[0]

    # repair_constants
    lcg_seed_val = struct.unpack_from('<I', flag, 17)[0]
    rc = lcg_expand(lcg_seed_val, sbox_first)
    rc_high4 = (rc[0] >> 28) & 0xF
    step3_bits = 16 + rc_high4

    # repair_semantics
    step2_amount = flag[21] & 0x1F
    raw_param = flag[22] | (flag[23] << 8) | (flag[24] << 16)
    mask = (1 << step3_bits) - 1 if step3_bits < 32 else 0xFFFFFFFF
    step3_param = raw_param & mask

    # core_compute
    IV_A = [0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE]
    xtea_delta = struct.unpack_from('<I', flag, 13)[0]

    def rol32(v, n):
        n &= 31
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    def step3_fn(sv, param):
        m = (1 << step3_bits) - 1 if step3_bits < 32 else 0xFFFFFFFF
        param &= m
        return (sv ^ (((sv >> 5) + param) & 0xFFFFFFFF)
                   ^ (((sv << 4) + (param >> 12)) & 0xFFFFFFFF)) & 0xFFFFFFFF

    def xtea_rnd(v0, v1, rc_val, da):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (da + rc_val))) & 0xFFFFFFFF
        t  = rol32(v0, step2_amount)
        v1 = (v1 + (step3_fn(t, rc_val) ^ (da + rc_val))) & 0xFFFFFFFF
        return v0, v1

    state = [0, 0, 0, 0]
    v0 = (state[0] ^ IV_A[0]) & 0xFFFFFFFF
    v1 = (state[1] ^ IV_A[1]) & 0xFFFFFFFF
    v2 = (state[2] ^ IV_A[2]) & 0xFFFFFFFF
    v3 = (state[3] ^ IV_A[3]) & 0xFFFFFFFF
    da = 0

    for bb in range(7):
        da = (da + xtea_delta) & 0xFFFFFFFF
        v0, v1 = xtea_rnd(v0, v1, rc[bb*2],   da)
        v2, v3 = xtea_rnd(v2, v3, rc[bb*2+1], da)

    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[14], da)
    v2, v3 = xtea_rnd(v2, v3, rc[15], da)
    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[16], da)
    v2, v3 = xtea_rnd(v2, v3, rc[17], da)
    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[18], da)
    v2, v3 = xtea_rnd(v2, v3, rc[19], da)
    v0 ^= sbox[v0 & 0xFF]; v1 ^= sbox[v1 & 0xFF]
    v2 ^= sbox[v2 & 0xFF]; v3 ^= sbox[v3 & 0xFF]
    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[20], da)
    v2, v3 = xtea_rnd(v2, v3, rc[21], da)
    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[22], da)
    v2, v3 = xtea_rnd(v2, v3, rc[23], da)

    final = bytearray(16)
    for i, v in enumerate([v0, v1, v2, v3]):
        struct.pack_into('<I', final, i*4, v)

    expected = bytes(enc_expected[i] ^ so_key[i] for i in range(16))
    ok = bytes(final) == expected
    print(f"  {label}: {'PASS' if ok else 'FAIL'}  final={final.hex()[:16]}...")
    return ok

r4 = verify_a(FLAG_A, soKey, ENC_A, "正确 flag")
r5 = verify_a(b'\x00'*25, soKey, ENC_A, "错误 flag (全零)")
assert r4 and not r5, "方案 A 验证失败"
print("方案 A: 全部通过\n")

# ════════════════════════════════════════════════════════════
# 50 字节交错 flag 验证
# ════════════════════════════════════════════════════════════
print("=" * 50)
print("50 字节交错 flag 验证")
print("=" * 50)

def interleave(a, b):
    out = bytearray(50)
    for i in range(25):
        out[i*2]   = a[i]
        out[i*2+1] = b[i]
    return bytes(out)

def deinterleave(inp):
    a = bytes(inp[i*2]   for i in range(25))
    b = bytes(inp[i*2+1] for i in range(25))
    return a, b

FLAG_50 = interleave(FLAG_A, FLAG_B)
print(f"50-byte flag (b64): {base64.b64encode(FLAG_50).decode()}")

# 模拟 nativeProcessInput 的顺序依赖逻辑
def verify_50(inp, so_key, label):
    a, b = deinterleave(inp)
    ok_a = verify_a(a, so_key, ENC_A, f"  {label} [A]")
    if not ok_a:
        print(f"  {label}: FAIL (方案 A 未通过，方案 B 不运行)")
        return False
    ok_b = verify_b(b, so_key, IV_B, ENC_B, EXPECTED_SOKEY_CHECK, f"  {label} [B]")
    ok = ok_a and ok_b
    print(f"  {label}: {'PASS' if ok else 'FAIL'}")
    return ok

r6 = verify_50(FLAG_50, soKey, "正确 50-byte flag")
r7 = verify_50(b'\x00'*50, soKey, "错误 50-byte flag (全零)")
# 方案 A 正确但方案 B 错误
wrong_b = interleave(FLAG_A, b'\x00'*25)
r8 = verify_50(wrong_b, soKey, "A 正确 B 错误")
assert r6 and not r7 and not r8, "50 字节交错验证失败"
print("50 字节交错: 全部通过\n")

print("=" * 50)
print("[autoctf] 验证完成 — 两方案均通过")
print("=" * 50)
print(f"\n方案 A flag (b64): {base64.b64encode(FLAG_A).decode()}")
print(f"方案 B flag (b64): {base64.b64encode(FLAG_B).decode()}")
print(f"50-byte flag (b64): {base64.b64encode(FLAG_50).decode()}")
