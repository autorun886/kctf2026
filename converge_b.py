#!/usr/bin/env python3
"""
converge_b.py — 迭代收敛 EXPECTED_SOKEY_CHECK 和 ENC_EXPECTED_STATE。

原理：
  EXPECTED_SOKEY_CHECK 嵌入 .so → 影响 .text CRC → 影响 soKey →
  影响 key_schedule → 影响 round_keys[15] → 影响 EXPECTED_SOKEY_CHECK

这是一个不动点问题。通过迭代求解：
  1. 从当前 .so 读取 soKey
  2. 用当前 flag 运行 key_schedule，得到 round_keys[15]
  3. 计算新的 EXPECTED_SOKEY_CHECK = round_keys[15] ^ soKey[12:16]
  4. 如果与当前值相同 → 收敛；否则更新 .c 文件，重新编译，回到 1

注意：由于 EXPECTED_SOKEY_CHECK 嵌入 .text，修改它会改变 CRC，
理论上可能不收敛。实际上因为 CRC 是非线性的，通常 2-3 次迭代后收敛。
如果不收敛，改用"不嵌入 .text"的方案：把 EXPECTED_SOKEY_CHECK 放在 .rodata。

用法：py -3 converge_b.py <libkctf.so路径> <key_expand.c路径> <jni_entry.c路径>
"""
import struct, sys, zlib, subprocess, re

SO_PATH       = sys.argv[1] if len(sys.argv) > 1 else \
    "app/build/intermediates/cxx/Debug/162k275h/obj/arm64-v8a/libkctf.so"
KEY_EXPAND_C  = sys.argv[2] if len(sys.argv) > 2 else \
    "app/src/main/cpp/src/key_expand.c"
JNI_ENTRY_C   = sys.argv[3] if len(sys.argv) > 3 else \
    "app/src/main/cpp/src/jni_entry.c"

FLAG_B = bytes([
    0x7A, 0xE3, 0x1B, 0x94, 0xD2, 0x56, 0xF8, 0x0C,
    0x41, 0xB7, 0x29, 0x8E, 0x63, 0xA5, 0xDF, 0x10,
    0x4B, 0xC8, 0x72, 0x3D, 0x96, 0x0F, 0xE4, 0x58, 0xAD
])
IV_B   = bytes([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10])

def ror64(x, n): return ((x >> n) | (x << (64 - n))) & ((1<<64)-1)
def rol64(x, n): return ((x << n) | (x >> (64 - n))) & ((1<<64)-1)

def derive_sokey(so_path):
    with open(so_path, "rb") as f: data = f.read()
    e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum     = struct.unpack_from('<H', data, 0x38)[0]
    for i in range(e_phnum):
        ph = data[e_phoff + i*e_phentsize : e_phoff + (i+1)*e_phentsize]
        if struct.unpack_from('<I', ph, 0)[0] == 1 and struct.unpack_from('<I', ph, 4)[0] & 1:
            off  = struct.unpack_from('<Q', ph, 8)[0]
            size = struct.unpack_from('<Q', ph, 0x20)[0]
            text = data[off : off + size]
            break
    crc = zlib.crc32(text) & 0xFFFFFFFF
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

def expand_key_material(flag_bytes):
    buf = bytearray(32); buf[:25] = flag_bytes; buf[25:] = bytes([0x5A]*7)
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(16):
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

def compute_check(flag, so_key):
    mat = bytearray(128)
    mat[:96] = expand_key_material(flag)
    for i in range(16): mat[96+i] = mat[i] ^ so_key[i]
    rk15 = struct.unpack_from('<I', mat, 15*4)[0]
    sokey_12 = struct.unpack_from('<I', so_key, 12)[0]
    return rk15 ^ sokey_12

def update_c_file(path, pattern, new_val_str):
    with open(path, 'r', encoding='utf-8') as f: content = f.read()
    new_content = re.sub(pattern, new_val_str, content)
    if new_content == content:
        return False
    with open(path, 'w', encoding='utf-8') as f: f.write(new_content)
    return True

def rebuild():
    result = subprocess.run(
        ["gradlew.bat", "assembleDebug"],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        shell=True
    )
    ok = "BUILD SUCCESSFUL" in result.stdout
    if not ok:
        print(result.stdout[-500:])
    return ok

# ── 迭代收敛 ─────────────────────────────────────────────
MAX_ITER = 8
prev_check = None

for iteration in range(MAX_ITER):
    soKey, crc = derive_sokey(SO_PATH)
    new_check = compute_check(FLAG_B, soKey)
    print(f"[iter {iteration}] CRC={crc:08x}  soKey={soKey.hex()[:16]}...  check={new_check:#010x}")

    if new_check == prev_check:
        print(f"[converge_b] 收敛！EXPECTED_SOKEY_CHECK = {new_check:#010x}")
        break

    prev_check = new_check

    # 更新 key_expand.c
    changed = update_c_file(
        KEY_EXPAND_C,
        r'#define EXPECTED_SOKEY_CHECK 0x[0-9a-fA-F]+u',
        f'#define EXPECTED_SOKEY_CHECK {new_check:#010x}u'
    )
    if not changed:
        print("[converge_b] 文件未变化，已收敛")
        break

    print(f"  -> 更新 EXPECTED_SOKEY_CHECK = {new_check:#010x}，重新编译...")
    if not rebuild():
        print("[converge_b] 编译失败，退出")
        sys.exit(1)
else:
    print("[converge_b] 警告：未在最大迭代次数内收敛")
    sys.exit(1)

# ── 收敛后计算最终 ENC_EXPECTED_STATE ────────────────────
import importlib.util, os, sys as _sys
# 直接内联 precompute_b 的核心逻辑
soKey, _ = derive_sokey(SO_PATH)

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

def generate_sbox(seed):
    sbox = list(range(256)); xs = seed & 0xFFFFFFFF
    for i in range(255, 0, -1):
        xs ^= (xs << 13) & 0xFFFFFFFF
        xs ^= (xs >> 17) & 0xFFFFFFFF
        xs ^= (xs << 5)  & 0xFFFFFFFF
        j = xs % (i + 1); sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox

def key_schedule_full(flag, so_key, expected_check):
    mat = bytearray(128)
    mat[:96] = expand_key_material(flag)
    for i in range(16): mat[96+i] = mat[i] ^ so_key[i]
    rk = [struct.unpack_from('<I', mat, i*4)[0] for i in range(16)]
    cfgs = []
    for i in range(16):
        b = mat[64+i]
        cfgs.append({'ss':(b>>0)&3,'sp':(b>>2)&3,'mm':(b>>4)&3,'nm':(b>>6)&3})
    seeds = [struct.unpack_from('<I', mat, 80+i*4)[0] for i in range(4)]
    delta = struct.unpack_from('<I', mat, 96)[0]
    check = rk[15] ^ struct.unpack_from('<I', so_key, 12)[0]
    diff  = check ^ expected_check
    poison = (((diff | ((~diff + 1) & 0xFFFFFFFF)) >> 31) & 1) * 0xDEADBEEF
    delta ^= poison
    return rk, cfgs, seeds, delta

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

def spn_encrypt_full(state, rk, cfgs, sboxes, delta):
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
            inp = state[col*4:col*4+4]; m = MDS[cfgs[rnd]['mm']]
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

rk, cfgs, seeds, delta = key_schedule_full(FLAG_B, soKey, new_check)
sboxes = [generate_sbox(s) for s in seeds]
final = spn_encrypt_full(list(IV_B), rk, cfgs, sboxes, delta)
enc = bytes(final[i] ^ soKey[i] for i in range(16))

print(f"\n[converge_b] 最终结果:")
print(f"  soKey:              {soKey.hex()}")
print(f"  EXPECTED_SOKEY_CHECK: {new_check:#010x}")
print(f"  ENC_EXPECTED_STATE: {enc.hex()}")

# 更新 jni_entry.c
enc_c = ', '.join(f'0x{b:02X}' for b in enc)
update_c_file(
    JNI_ENTRY_C,
    r'(static const uint8_t ENC_EXPECTED_STATE\[STATE_LEN\] = \{)[^}]*(})',
    f'\\g<1>\n    {enc_c}\n\\g<2>'
)
print(f"  jni_entry.c 已更新")

# 最终编译
print("  最终编译...")
if rebuild():
    print("[autoctf] converge_b 完成 — BUILD SUCCESSFUL")
else:
    print("[converge_b] 最终编译失败")
    sys.exit(1)
