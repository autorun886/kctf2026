#!/usr/bin/env python3
"""
extract_bb_addrs.py — 从 libkctf.so 自动提取 core_compute 的 BB 关键地址。
输出可直接粘贴到 repair_cfg.c 的 #define 区域。
"""
import struct, sys, re

SO_PATH = sys.argv[1] if len(sys.argv) > 1 else \
    "app/build/intermediates/cxx/Debug/162k275h/obj/arm64-v8a/libkctf.so"

with open(SO_PATH, "rb") as f:
    data = f.read()

# ELF64：找 PT_LOAD PF_X 段的文件偏移和虚拟地址
e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum     = struct.unpack_from('<H', data, 0x38)[0]
text_foff = text_vaddr = text_size = 0
for i in range(e_phnum):
    ph = data[e_phoff + i*e_phentsize : e_phoff + (i+1)*e_phentsize]
    p_type   = struct.unpack_from('<I', ph, 0x00)[0]
    p_flags  = struct.unpack_from('<I', ph, 0x04)[0]
    p_offset = struct.unpack_from('<Q', ph, 0x08)[0]
    p_vaddr  = struct.unpack_from('<Q', ph, 0x10)[0]
    p_filesz = struct.unpack_from('<Q', ph, 0x20)[0]
    if p_type == 1 and (p_flags & 0x1):  # PT_LOAD PF_X
        text_foff  = p_offset
        text_vaddr = p_vaddr
        text_size  = p_filesz
        break

def vaddr_to_foff(va):
    return text_foff + (va - text_vaddr)

def read_u32_va(va):
    return struct.unpack_from('<I', data, vaddr_to_foff(va))[0]

# 找 core_compute 符号地址
nm_path = SO_PATH.replace("libkctf.so", "")
import subprocess, os
NDK = os.path.expanduser("~/AppData/Local/Android/Sdk/ndk/27.0.12077973")
NM  = f"{NDK}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
out = subprocess.check_output([NM, "--defined-only", SO_PATH], text=True)
syms = {}
for line in out.splitlines():
    parts = line.split()
    if len(parts) == 3:
        syms[parts[2]] = int(parts[0], 16)

core_va = syms.get("core_compute", 0)
print(f"core_compute VA: {core_va:08x}")

# 扫描 core_compute 函数体，找关键指令
# 函数大小估计：找下一个符号
sorted_syms = sorted((v, k) for k, v in syms.items())
core_size = 0x800  # 保守估计
for va, name in sorted_syms:
    if va > core_va:
        core_size = va - core_va
        break

print(f"core_compute size: {core_size:#x}")

results = {}
va = core_va
end_va = core_va + core_size

while va < end_va:
    insn = read_u32_va(va)

    # B 指令：[31:26] = 000101
    if (insn >> 26) == 0x05:
        imm26 = insn & 0x03FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        target = (va + imm26 * 4) & 0xFFFFFFFF
        off_from_base = va - text_vaddr
        tgt_off = target - text_vaddr
        results.setdefault('b_insns', []).append((off_from_base, tgt_off, insn))

    # TBZ/TBNZ：[31:24] = 0x36 / 0x37
    if (insn >> 24) in (0x36, 0x37):
        off_from_base = va - text_vaddr
        bit_num = (insn >> 19) & 0x1F
        imm14   = (insn >> 5) & 0x3FFF
        if imm14 & (1 << 13): imm14 -= (1 << 14)
        target  = (va + imm14 * 4) & 0xFFFFFFFF
        tgt_off = target - text_vaddr
        results.setdefault('tbz_insns', []).append((off_from_base, bit_num, tgt_off, insn))

    # ADR：[31]=0, [28:24]=10000
    if (insn & 0x9F000000) == 0x10000000 and (insn >> 31) == 0:
        immlo = (insn >> 29) & 0x3
        immhi = (insn >>  5) & 0x7FFFF
        imm21 = (immhi << 2) | immlo
        if imm21 & (1 << 20): imm21 -= (1 << 21)
        target  = (va + imm21) & 0xFFFFFFFF
        off_from_base = va - text_vaddr
        tgt_off = target - text_vaddr
        # 检查下一条是否是 BR
        next_insn = read_u32_va(va + 4)
        if (next_insn & 0xFFFFFC1F) == 0xD61F0000:  # BR xN
            results.setdefault('adr_br', []).append((off_from_base, tgt_off, insn))

    # MOV xN, xN（dead block 特征：0xAA0903E9 等）
    # mov x9,x9 = 0xAA0903E9, mov x10,x10 = 0xAA0A03EA
    if insn in (0xAA0903E9, 0xAA0A03EA, 0xAA0B03EB, 0xAA0C03EC):
        off_from_base = va - text_vaddr
        results.setdefault('dead_block', []).append(off_from_base)

    va += 4

print("\n=== B 指令（无条件跳转）===")
for off, tgt, insn in results.get('b_insns', []):
    print(f"  {off:#06x}: b {tgt:#06x}  [{insn:08x}]")

print("\n=== TBZ/TBNZ 指令 ===")
for off, bit, tgt, insn in results.get('tbz_insns', []):
    print(f"  {off:#06x}: tbz/tbnz bit#{bit} -> {tgt:#06x}  [{insn:08x}]")

print("\n=== ADR+BR 组合 ===")
for off, tgt, insn in results.get('adr_br', []):
    print(f"  {off:#06x}: adr -> {tgt:#06x}  [{insn:08x}]")

print("\n=== Dead block 指令 ===")
for off in results.get('dead_block', []):
    print(f"  {off:#06x}")

# 推断各破坏点
b_insns = results.get('b_insns', [])
tbz_insns = results.get('tbz_insns', [])
adr_br = results.get('adr_br', [])
dead_blocks = results.get('dead_block', [])

if tbz_insns:
    bb2_tbz_off, bb2_bit, bb3_tgt, _ = tbz_insns[0]
    print(f"\n[推断] BB2_TBZ_OFF    = {bb2_tbz_off:#06x}  (tbz bit#{bb2_bit} -> {bb3_tgt:#06x})")

if adr_br:
    bb6_adr_off, bb7_tgt, _ = adr_br[0]
    print(f"[推断] BB6_ADR_OFF    = {bb6_adr_off:#06x}")
    print(f"[推断] BB7_ENTRY_OFF  = {bb7_tgt:#06x}  (adr 目标，即 BB7 入口)")

if dead_blocks:
    dead_off = dead_blocks[0]
    print(f"[推断] DEAD_BLOCK_OFF = {dead_off:#06x}")
    # BB4 B 指令应该在 dead block 之前
    for off, tgt, insn in b_insns:
        if tgt == dead_off or (off < dead_off and tgt > dead_off):
            print(f"[推断] BB4_BRANCH_OFF = {off:#06x}  (b -> {tgt:#06x})")
            break

# BB0 B 指令：第一个 B 指令（跳到 BB0 入口之后的第一个 BB）
if b_insns:
    bb0_off, bb1_tgt, _ = b_insns[0]
    print(f"[推断] BB0_BRANCH_OFF = {bb0_off:#06x}  (b -> {bb1_tgt:#06x} = BB1 入口)")

print(f"\n// 粘贴到 repair_cfg.c:")
if b_insns and tbz_insns and adr_br and dead_blocks:
    bb0_off = b_insns[0][0]
    bb1_tgt = b_insns[0][1]
    bb2_off = tbz_insns[0][0]
    bb7_tgt = adr_br[0][1]
    bb6_off = adr_br[0][0]
    dead_off = dead_blocks[0]
    # BB4 B 指令
    bb4_off = None
    for off, tgt, insn in b_insns:
        if tgt == dead_off:
            bb4_off = off
            break
    if bb4_off is None:
        # 找 dead block 前最近的 B 指令
        for off, tgt, insn in reversed(b_insns):
            if off < dead_off:
                bb4_off = off
                break
    # BB5 入口（dead block 之后的第一个 B 指令目标）
    bb5_tgt = None
    for off, tgt, insn in b_insns:
        if off > dead_off:
            bb5_tgt = tgt
            break

    print(f"#define BB0_BRANCH_OFF  {bb0_off:#06x}u  /* b -> BB1 {bb1_tgt:#06x} */")
    print(f"#define BB2_TBZ_OFF     {bb2_off:#06x}u  /* tbz -> BB3 */")
    if bb4_off:
        print(f"#define BB4_BRANCH_OFF  {bb4_off:#06x}u  /* b -> dead block {dead_off:#06x} */")
    print(f"#define BB6_ADR_OFF     {bb6_off:#06x}u  /* adr+br -> BB7 */")
    print(f"#define BB7_ENTRY_OFF   {bb7_tgt:#06x}u  /* BB7 入口 */")
    print(f"#define DEAD_BLOCK_OFF  {dead_off:#06x}u  /* dead block 入口 */")
