#!/usr/bin/env python3
"""
Phase 6A 预计算脚本
从 Debug build 的 libkctf.so 反推方案 A 的 flag 各字段，
正向模拟 core_compute，计算 ENC_EXPECTED_STATE_A。

用法：python3 precompute_a.py <libkctf.so路径> <soKey_hex>
soKey 可先用 precompute_sokey.py 计算。
"""

import struct, sys, zlib

SO_PATH = sys.argv[1] if len(sys.argv) > 1 else \
    "app/build/intermediates/cxx/Debug/162k275h/obj/arm64-v8a/libkctf.so"

# ── ELF 解析：找 .text section ────────────────────────────
def parse_elf_text_section(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b'\x7fELF'
    e_shoff     = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum     = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx  = struct.unpack_from('<H', data, 62)[0]
    sh = data[e_shoff + e_shstrndx*e_shentsize : e_shoff + (e_shstrndx+1)*e_shentsize]
    strtab_off  = struct.unpack_from('<Q', sh, 24)[0]
    strtab_size = struct.unpack_from('<Q', sh, 32)[0]
    strtab = data[strtab_off : strtab_off + strtab_size]
    for i in range(e_shnum):
        sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
        name_idx = struct.unpack_from('<I', sh, 0)[0]
        end = strtab.index(b'\x00', name_idx)
        if strtab[name_idx:end] == b'.text':
            off  = struct.unpack_from('<Q', sh, 24)[0]
            size = struct.unpack_from('<Q', sh, 32)[0]
            return data, off, size
    raise RuntimeError(".text section not found")

data, TEXT_SECTION_OFF, TEXT_SECTION_SIZE = parse_elf_text_section(SO_PATH)

def read_u32(off):
    # off 是相对文件起始的偏移（.text section 内的虚拟地址 = 文件偏移，因为 vaddr=foff）
    return struct.unpack_from('<I', data, off)[0]

# ── 破坏点偏移（从 extract_bb_addrs.py 动态提取）────────
import subprocess, os
NDK = os.path.expanduser("~/AppData/Local/Android/Sdk/ndk/27.0.12077973")
NM  = f"{NDK}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"

def get_bb_addrs(so_path):
    """调用 extract_bb_addrs.py 获取 BB 地址"""
    result = subprocess.run(
        ["py", "-3", "extract_bb_addrs.py", so_path],
        capture_output=True, text=True, encoding='utf-8', errors='replace'
    )
    addrs = {}
    for line in result.stdout.splitlines():
        for key in ["BB0_BRANCH_OFF", "BB2_TBZ_OFF", "BB4_BRANCH_OFF",
                    "BB6_ADR_OFF", "BB7_ENTRY_OFF", "DEAD_BLOCK_OFF"]:
            if key in line and "0x" in line:
                import re
                m = re.search(r'0x([0-9a-fA-F]+)', line)
                if m:
                    addrs[key] = int(m.group(1), 16)
    return addrs

bb = get_bb_addrs(SO_PATH)
BB0_BRANCH_OFF = bb["BB0_BRANCH_OFF"]
BB2_TBZ_OFF    = bb["BB2_TBZ_OFF"]
BB4_BRANCH_OFF = bb["BB4_BRANCH_OFF"]
BB6_ADR_OFF    = bb["BB6_ADR_OFF"]
BB7_ENTRY_OFF  = bb["BB7_ENTRY_OFF"]
DEAD_OFF       = bb["DEAD_BLOCK_OFF"]
BB1_OFF        = BB0_BRANCH_OFF + 4   # B 指令目标（BB1 入口）
BB5_OFF        = DEAD_OFF + 16        # dead block 之后（4 条 mov 指令 = 16 字节）

print(f"BB0_BRANCH={BB0_BRANCH_OFF:#06x} BB2_TBZ={BB2_TBZ_OFF:#06x} "
      f"BB4_BRANCH={BB4_BRANCH_OFF:#06x} BB6_ADR={BB6_ADR_OFF:#06x}")

# ── 读取各破坏点的原始（未破坏）指令值 ───────────────────
b0_insn   = read_u32(BB0_BRANCH_OFF)
tbz_insn  = read_u32(BB2_TBZ_OFF)
b4_insn   = read_u32(BB4_BRANCH_OFF)
adr6_insn = read_u32(BB6_ADR_OFF)

print(f"BB0 B    insn: {b0_insn:08x}")
print(f"BB2 TBZ  insn: {tbz_insn:08x}")
print(f"BB4 B    insn: {b4_insn:08x}")
print(f"BB6 ADR  insn: {adr6_insn:08x}")

# ── 计算 soKey（只读 .text section）─────────────────────
text_bytes = data[TEXT_SECTION_OFF : TEXT_SECTION_OFF + TEXT_SECTION_SIZE]
crc_val = zlib.crc32(text_bytes) & 0xFFFFFFFF
print(f"\nCRC32(.text section): {crc_val:08x}")

EXPAND = [0xA3F1B28C7D4E5F60, 0x9C8B7A6D5E4F3021,
          0x1F2E3D4C5B6A7980, 0xD0E1F2038495A6B7]
MUL = 0x5851F42D4C957F2D
ADD = 0x14057B7EF767814F
MASK64 = (1 << 64) - 1

soKey = bytearray(16)
for i in range(4):
    m = ((crc_val ^ EXPAND[i]) * MUL + ADD) & MASK64
    soKey[i*4]   = (m >> 24) & 0xFF
    soKey[i*4+1] = (m >> 16) & 0xFF
    soKey[i*4+2] = (m >>  8) & 0xFF
    soKey[i*4+3] = (m      ) & 0xFF
print(f"soKey: {soKey.hex()}")

# ── 反推 flag 各字段 ──────────────────────────────────────
# flag[0:4]：BB0 B 指令的 imm26 XOR key
# 正确 imm26 = (BB1_OFF - BB0_BRANCH_OFF) / 4 = (0x3540 - 0x353C) / 4 = 1
BB1_OFF = 0x3540
correct_imm26 = (BB1_OFF - BB0_BRANCH_OFF) // 4
broken_imm26  = b0_insn & 0x03FFFFFF
flag_0_3 = (broken_imm26 ^ correct_imm26) & 0x03FFFFFF
flag_bytes = bytearray(25)
struct.pack_into('<I', flag_bytes, 0, flag_0_3)
print(f"\nflag[0:4] = {flag_bytes[0:4].hex()}  (BB0 imm26 key)")

# flag[4]：tbz bit 字段 XOR key（[22:19]）
# 正确 bit = 0（测试 bit 0），broken bit 由发布时 XOR 决定
# 这里我们选择 flag[4] = 0（不破坏 tbz），即发布时不修改 tbz
# 实际发布时需要选一个非零值使 tbz 测试错误的 bit
# 选 flag[4] = 0x01（XOR 到 bit[19]，使 tbz 测试 bit 1 而非 bit 0）
flag_bytes[4] = 0x01
print(f"flag[4]   = {flag_bytes[4]:02x}  (tbz bit field key)")

# flag[5:9]：BB4 B 指令 imm26 XOR key
# 正确目标 = BB5 入口 0x3700，broken 目标 = dead block 0x36EC
correct_b4_imm26 = ((BB5_OFF - BB4_BRANCH_OFF) // 4) & 0x03FFFFFF
dead_imm26 = ((DEAD_OFF - BB4_BRANCH_OFF) // 4) & 0x03FFFFFF
flag_5_8 = (correct_b4_imm26 ^ dead_imm26) & 0x03FFFFFF
struct.pack_into('<I', flag_bytes, 5, flag_5_8)
print(f"flag[5:9] = {flag_bytes[5:9].hex()}  (BB4 dead block key)")

# flag[9:13]：BB6 adr imm21 XOR key（与 soKey[0:4] 联合）
# 正确目标 = BB7 入口 0x37B4
# adr 指令：imm21 = target - PC，PC = BB6_ADR_OFF
correct_imm21 = BB7_ENTRY_OFF - BB6_ADR_OFF  # = 0x10
# 当前 adr 指令的 imm21
immlo = (adr6_insn >> 29) & 0x3
immhi = (adr6_insn >>  5) & 0x7FFFF
current_imm21 = (immhi << 2) | immlo
if current_imm21 & (1 << 20): current_imm21 -= (1 << 21)  # 符号扩展
print(f"  adr current imm21 = {current_imm21} (should be {correct_imm21})")
# 发布时 adr 被破坏：imm21 XOR key，key = flag[9:13] ^ soKey[0:4]
# 我们选 flag[9:13] = soKey[0:4]（使 key = 0，即不破坏 adr）
# 实际发布时选一个非零 key 使 adr 指向错误地址
# 选 flag[9:13] = soKey[0:4] XOR 0x00000001（破坏 immlo 的 bit 0）
sokey_0_3 = struct.unpack_from('<I', soKey, 0)[0]
flag_9_12 = (sokey_0_3 ^ 0x00000001) & 0xFFFFFFFF
struct.pack_into('<I', flag_bytes, 9, flag_9_12)
print(f"flag[9:13]= {flag_bytes[9:13].hex()}  (adr imm21 key)")

# flag[13:17]：xtea_delta 直接值
# 选标准 XTEA delta
XTEA_DELTA = 0x9E3779B9
struct.pack_into('<I', flag_bytes, 13, XTEA_DELTA)
print(f"flag[13:17]={flag_bytes[13:17].hex()}  (xtea_delta)")

# flag[17:21]：LCG seed（混入 sbox[0]，但 sbox 此时未知，先用 0）
# 选一个固定 seed，Phase 7 验证后如需调整再改
LCG_SEED = 0xDEADC0DE
struct.pack_into('<I', flag_bytes, 17, LCG_SEED)
print(f"flag[17:21]={flag_bytes[17:21].hex()}  (LCG seed)")

# flag[21]：step2 循环左移量（选 7，非零非平凡）
flag_bytes[21] = 7
print(f"flag[21]  = {flag_bytes[21]:02x}  (step2 amount)")

# flag[22:25]：step3 param（先用 0，Phase 7 验证后调整）
flag_bytes[22] = 0x42
flag_bytes[23] = 0x13
flag_bytes[24] = 0x37
print(f"flag[22:25]={flag_bytes[22:25].hex()}  (step3 param)")

print(f"\nflag (hex): {flag_bytes.hex()}")
import base64
print(f"flag (b64): {base64.b64encode(flag_bytes).decode()}")

# ── 正向模拟 core_compute ─────────────────────────────────
# 先模拟 repair_constants 得到 round_constants
def lcg_expand(seed, sbox_first=0):
    lcg = (seed ^ (sbox_first * 0x01010101)) & 0xFFFFFFFF
    rc = []
    for _ in range(32):
        lcg = (lcg * 1664525 + 1013904223) & 0xFFFFFFFF
        rc.append(lcg)
    return rc

# sbox_first 依赖 repair_sbox，repair_sbox 依赖 dispatch_table[0]
# dispatch_table[0] = adr 指令地址（repair_cfg 存入），低 8 bit 作为偏移
# 当前 dispatch_table[0] = BB6_ADR_OFF（repair_cfg 存的是指令地址）
# 实际运行时是运行时地址，这里用偏移的低 8 bit 模拟
cfg_dep = BB6_ADR_OFF & 0xFF  # = 0xA4

# repair_sbox：xorshift32 展开 key_stream，XOR 还原 sbox_shipped
# sbox_shipped 发布时是什么？需要知道"破坏后的 sbox"
# 当前代码里 sbox_shipped 初始值未设置（全零），repair_sbox 会 XOR 还原
# 正确 sbox 应该是双射，这里先用恒等映射作为"发布时的 sbox"
# 实际发布时需要预先破坏 sbox_shipped，Phase 6A.3 完成后替换
sbox_seed = struct.unpack_from('<I', flag_bytes, 9)[0]
xs = sbox_seed
key_stream = []
for _ in range(256):
    xs ^= (xs << 13) & 0xFFFFFFFF
    xs ^= (xs >> 17) & 0xFFFFFFFF
    xs ^= (xs << 5)  & 0xFFFFFFFF
    key_stream.append(xs & 0xFF)

# 假设 sbox_shipped 发布时全零，repair_sbox XOR 后得到 key_stream 本身
sbox = [0] * 256
offset = cfg_dep
for i in range(256):
    sbox[(i + offset) & 0xFF] ^= key_stream[i]
sbox_first = sbox[0]
print(f"\nsbox[0] = {sbox_first:02x}")

# repair_constants
lcg_seed = struct.unpack_from('<I', flag_bytes, 17)[0]
rc = lcg_expand(lcg_seed, sbox_first)
print(f"round_constants[0] = {rc[0]:08x}")

# repair_semantics
rc_high4 = (rc[0] >> 28) & 0xF
step3_bits = 16 + rc_high4
step2_amount = flag_bytes[21] & 0x1F
raw_param = flag_bytes[22] | (flag_bytes[23] << 8) | (flag_bytes[24] << 16)
mask = (1 << step3_bits) - 1 if step3_bits < 32 else 0xFFFFFFFF
step3_param = raw_param & mask
print(f"step2_amount={step2_amount}, step3_bits={step3_bits}, step3_param={step3_param:08x}")

# core_compute 模拟
IV_A = [0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE]

def rol32(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def step3_fn(state_val, param, bits):
    mask = (1 << bits) - 1 if bits < 32 else 0xFFFFFFFF
    param &= mask
    return (state_val ^ (((state_val >> 5) + param) & 0xFFFFFFFF)
                      ^ (((state_val << 4) + (param >> 12)) & 0xFFFFFFFF)) & 0xFFFFFFFF

def xtea_round(v0, v1, rc_val, delta_acc):
    v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (delta_acc + rc_val))) & 0xFFFFFFFF
    t  = rol32(v0, step2_amount)
    v1 = (v1 + (step3_fn(t, rc_val, step3_bits) ^ (delta_acc + rc_val))) & 0xFFFFFFFF
    return v0, v1

state = [0, 0, 0, 0]  # 初始 state（jni_entry_a 传入全零）
v0 = (state[0] ^ IV_A[0]) & 0xFFFFFFFF
v1 = (state[1] ^ IV_A[1]) & 0xFFFFFFFF
v2 = (state[2] ^ IV_A[2]) & 0xFFFFFFFF
v3 = (state[3] ^ IV_A[3]) & 0xFFFFFFFF
delta_acc = 0

# BB0~BB6：每 BB 2 轮，共 14 轮（BB0~BB6 各 2 轮）
for bb in range(7):
    delta_acc = (delta_acc + XTEA_DELTA) & 0xFFFFFFFF
    v0, v1 = xtea_round(v0, v1, rc[bb*2],   delta_acc)
    v2, v3 = xtea_round(v2, v3, rc[bb*2+1], delta_acc)

# BB7：2 轮 + S-Box 混入 + 4 轮
delta_acc = (delta_acc + XTEA_DELTA) & 0xFFFFFFFF
v0, v1 = xtea_round(v0, v1, rc[14], delta_acc)
v2, v3 = xtea_round(v2, v3, rc[15], delta_acc)

delta_acc = (delta_acc + XTEA_DELTA) & 0xFFFFFFFF
v0, v1 = xtea_round(v0, v1, rc[16], delta_acc)
v2, v3 = xtea_round(v2, v3, rc[17], delta_acc)

delta_acc = (delta_acc + XTEA_DELTA) & 0xFFFFFFFF
v0, v1 = xtea_round(v0, v1, rc[18], delta_acc)
v2, v3 = xtea_round(v2, v3, rc[19], delta_acc)

# S-Box 混入
v0 ^= sbox[v0 & 0xFF]
v1 ^= sbox[v1 & 0xFF]
v2 ^= sbox[v2 & 0xFF]
v3 ^= sbox[v3 & 0xFF]

delta_acc = (delta_acc + XTEA_DELTA) & 0xFFFFFFFF
v0, v1 = xtea_round(v0, v1, rc[20], delta_acc)
v2, v3 = xtea_round(v2, v3, rc[21], delta_acc)

delta_acc = (delta_acc + XTEA_DELTA) & 0xFFFFFFFF
v0, v1 = xtea_round(v0, v1, rc[22], delta_acc)
v2, v3 = xtea_round(v2, v3, rc[23], delta_acc)

final_state = bytearray(16)
for i, v in enumerate([v0, v1, v2, v3]):
    struct.pack_into('<I', final_state, i*4, v)

print(f"\nfinal_state: {final_state.hex()}")

# ENC_EXPECTED_STATE_A = final_state XOR soKey
enc = bytearray(16)
for i in range(16):
    enc[i] = final_state[i] ^ soKey[i]
print(f"ENC_EXPECTED_STATE_A: {enc.hex()}")

# 输出 C 数组格式
def to_c_array(name, data):
    vals = ', '.join(f'0x{b:02X}' for b in data)
    return f"static const uint8_t {name}[{len(data)}] = {{{vals}}};"

print(f"\n// 填入 jni_entry_a.c:")
print(to_c_array("ENC_EXPECTED_STATE_A", enc))
print(f"\n// 填入 repair_constants.c (KPT/KCT 需另行生成):")
print(f"// xtea_delta = 0x{XTEA_DELTA:08X}u")
print(f"// LCG seed   = 0x{LCG_SEED:08X}u")
