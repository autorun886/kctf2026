#!/usr/bin/env python3
"""
converge.py -- KCTF2026 自动化常量收敛脚本

流程：
  1. Release 构建
  2. 从 .so 提取 .text 段 → CRC32 → soKey
  3. 提取 BB 地址、计算 KCT/KOUT/ENC_EXPECTED_STATE
  4. 更新所有源文件中的常量
  5. 重新构建，对比 CRC → 稳定则收敛，否则回到步骤 1
  6. 收敛后运行 verify.py 确认两方案通过
  7. 输出最终 50-byte flag

用法：py -3 converge.py [--release | --debug] [--max-iter N]
     设置 --release 使用 Release build，--debug 使用 Debug build
"""

import struct, zlib, subprocess, re, sys, os, base64, argparse

ROOT = os.path.dirname(os.path.abspath(__file__))

# ── 命令行参数 ───────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--release", action="store_true", default=True, help="Use Release build")
parser.add_argument("--debug",   action="store_true", help="Use Debug build")
parser.add_argument("--max-iter", type=int, default=20, help="Max iterations")
parser.add_argument("--dry-run",  action="store_true", help="Compute but don't write files")
args = parser.parse_args()

BUILD_TYPE   = "debug" if args.debug else "release"
GRADLE_TASK  = f"assemble{BUILD_TYPE.capitalize()}"

# ── 工具函数 ─────────────────────────────────────────────────────
def log(msg):
    print(f"[autoctf] {msg}", flush=True)

def ror64(x, n): return ((x >> n) | (x << (64 - n))) & ((1 << 64) - 1)
def rol64(x, n): return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)

def _crc32_16(data):
    """CRC32 of 16 bytes using half-byte table (matches C state_checksum)."""
    T = [0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
         0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
         0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
         0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C]
    crc = 0xFFFFFFFF
    for b in data[:16]:
        crc ^= b
        crc = ((crc >> 4) ^ T[crc & 0x0F]) & 0xFFFFFFFF
        crc = ((crc >> 4) ^ T[crc & 0x0F]) & 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF

# ── 方案 B flag（固定随机字节，不可猜测格式）──────────────────
# 由 hashlib.sha256(b"KCTF2026_scheme_B_flag_seed_v2").digest()[:25] 生成
FLAG_B = bytes([
    0x7A, 0xE3, 0x1B, 0x94, 0xD2, 0x56, 0xF8, 0x0C,
    0x41, 0xB7, 0x29, 0x8E, 0x63, 0xA5, 0xDF, 0x10,
    0x4B, 0xC8, 0x72, 0x3D, 0x96, 0x0F, 0xE4, 0x58, 0xAD
])

# ── IV2（方案 B 第二次 SPN，唯一性约束）────────────────────────
IV2_B = [0xA5, 0x5A, 0xC3, 0x3C, 0xF0, 0x0F, 0x69, 0x96,
         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]


# ── 步骤 1: 构建 ─────────────────────────────────────────────────
def find_gradlew():
    """Find gradlew.bat or gradlew, return (executable, args) for subprocess."""
    candidates = [
        os.path.join(ROOT, "gradlew.bat"),
        os.path.join(ROOT, "gradlew"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    raise FileNotFoundError("gradlew not found")


def build():
    """Run gradle clean + assemble, return True if successful."""
    gw = find_gradlew()
    log(f"Building: clean + {GRADLE_TASK}")
    # Clean first to avoid stale build cache causing CRC oscillation
    r = subprocess.run([gw, "clean", GRADLE_TASK], cwd=ROOT,
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace",
                       shell=(gw.endswith(".bat")))
    out = r.stdout + r.stderr
    ok = "BUILD SUCCESSFUL" in out
    if not ok:
        # Print tail for debugging
        for line in out.splitlines()[-15:]:
            print(f"  [BUILD] {line}")
        log("BUILD FAILED!")
    else:
        log("BUILD SUCCESSFUL")
    return ok


# ── 步骤 2: 找 .so 文件 ──────────────────────────────────────────
def find_so():
    """Find the Release .so under app/build. Prefer unstripped, fall back to stripped."""
    patterns = [
        # Unstripped (has symbols, needed for extract_bb_addrs)
        f"app/build/intermediates/merged_native_libs/{BUILD_TYPE}/merge{BUILD_TYPE.capitalize()}NativeLibs/out/lib/arm64-v8a/libkctf.so",
        # Stripped
        f"app/build/intermediates/stripped_native_libs/{BUILD_TYPE}/strip{BUILD_TYPE.capitalize()}DebugSymbols/out/lib/arm64-v8a/libkctf.so",
    ]
    for p in patterns:
        full = os.path.join(ROOT, p)
        if os.path.isfile(full):
            return full
    # Last resort: glob
    for root_dir, _, files in os.walk(os.path.join(ROOT, "app/build")):
        for f in files:
            if f == "libkctf.so" and BUILD_TYPE in root_dir and "arm64-v8a" in root_dir:
                return os.path.join(root_dir, f)
    raise FileNotFoundError(f"libkctf.so not found for {BUILD_TYPE}")


# ── Oracle shellcode XOR 加密（构建后处理）──────────────────────
# 与 seeds_oracle.c 中 get_oracle_key() 的 3-share 派生完全一致
_KDF_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
           0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

def _mba_add(a, b):
    return ((a ^ b) + ((a & b) << 1)) & 0xFFFFFFFF

def _mba_xor(a, b):
    return ((a | b) - (a & b)) & 0xFFFFFFFF

def _mba_f(x, k):
    x = _mba_add(x, k)
    x = _mba_xor(x, (x >> 16))
    x = (x * 0x45D9F3B) & 0xFFFFFFFF
    x = _mba_xor(x, (x >> 16))
    return x

def _compute_share0_first():
    """Share 0 前 8 字节: Feistel(c0^c2, c1^c3, keys=c4..c7)"""
    c = _KDF_IV
    L = _mba_xor(c[0], c[2])
    R = _mba_xor(c[1], c[3])
    for i in range(4):
        tmp = R
        R = _mba_xor(L, _mba_f(R, c[4 + i]))
        L = tmp
    return struct.pack('<II', L, R)

def _compute_share0_second():
    """Share 0 后 8 字节: Feistel(c4^c6, c5^c7, keys=c0..c3)"""
    c = _KDF_IV
    L = _mba_xor(c[4], c[6])
    R = _mba_xor(c[5], c[7])
    for i in range(4):
        tmp = R
        R = _mba_xor(L, _mba_f(R, c[i]))
        L = tmp
    return struct.pack('<II', L, R)

def _crc32_half_byte(data):
    """半字节 CRC32（与 C 代码一致）"""
    T = [0x00000000,0x1DB71064,0x3B6E20C8,0x26D930AC,
         0x76DC4190,0x6B6B51F4,0x4DB26158,0x5005713C,
         0xEDB88320,0xF00F9344,0xD6D6A3E8,0xCB61B38C,
         0x9B64C2B0,0x86D3D2D4,0xA00AE278,0xBDBDF21C]
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        crc = ((crc >> 4) ^ T[crc & 0x0F]) & 0xFFFFFFFF
        crc = ((crc >> 4) ^ T[crc & 0x0F]) & 0xFFFFFFFF
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF

def _compute_share1(so_path):
    """Share 1: expand_key_material 前 128 字节代码的 CRC32"""
    # 找到 expand_key_material 的文件偏移
    ndk = os.path.expanduser("~/AppData/Local/Android/Sdk/ndk/27.0.12077973")
    nm = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
    if not os.path.isfile(nm):
        for ndk_dir in ["27.0.12077973", "26.3.11579264", "25.2.9519653"]:
            ndk = os.path.expanduser(f"~/AppData/Local/Android/Sdk/ndk/{ndk_dir}")
            nm = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
            if os.path.isfile(nm):
                break

    with open(so_path, "rb") as f:
        data = f.read()

    out = subprocess.check_output([nm, "--defined-only", so_path], text=True,
                                  encoding="utf-8", errors="replace")
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)

    func_va = syms.get("expand_key_material", 0)
    if not func_va:
        raise RuntimeError("expand_key_material symbol not found")

    # VA → file offset
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    func_foff = 0
    for i in range(e_phnum):
        ph = data[e_phoff + i*e_phentsize:e_phoff + (i+1)*e_phentsize]
        p_type = struct.unpack_from("<I", ph, 0)[0]
        if p_type != 1: continue
        p_offset = struct.unpack_from("<Q", ph, 8)[0]
        p_vaddr = struct.unpack_from("<Q", ph, 16)[0]
        p_filesz = struct.unpack_from("<Q", ph, 32)[0]
        if p_vaddr <= func_va < p_vaddr + p_filesz:
            func_foff = p_offset + (func_va - p_vaddr)
            break

    code = data[func_foff:func_foff + 128]

    # 前 8 字节: CRC(code[0:32]) + CRC(code[32:64])
    crc_a = _crc32_half_byte(code[0:32])
    crc_b = _crc32_half_byte(code[32:64])
    first8 = struct.pack('<II', crc_a, crc_b)

    # 后 8 字节: CRC(code[64:96]) + CRC(code[96:128])
    crc_c = _crc32_half_byte(code[64:96])
    crc_d = _crc32_half_byte(code[96:128])
    second8 = struct.pack('<II', crc_c, crc_d)

    return first8, second8

def _compute_share2(soKey):
    """Share 2: soKey 变换"""
    sk = soKey
    # 前 8 字节
    first8 = bytearray(8)
    for i in range(8):
        a = sk[i]
        b = sk[(i + 3) & 0x0F]
        c = sk[(i + 7) & 0x0F]
        first8[i] = a ^ ((b << 3) | (b >> 5)) & 0xFF ^ ((c << 5) | (c >> 3)) & 0xFF
    # 修正：需要整体 & 0xFF
    first8_fixed = bytearray(8)
    for i in range(8):
        a = sk[i]
        b = sk[(i + 3) & 0x0F]
        c = sk[(i + 7) & 0x0F]
        first8_fixed[i] = (a ^ (((b << 3) | (b >> 5)) & 0xFF) ^ (((c << 5) | (c >> 3)) & 0xFF)) & 0xFF

    # 后 8 字节
    second8 = bytearray(8)
    for i in range(8):
        a = sk[8 + i]
        b = sk[(i + 5) & 0x0F]
        c = sk[(i + 11) & 0x0F]
        second8[i] = (a ^ (((b << 2) | (b >> 6)) & 0xFF) ^ (((c << 6) | (c >> 2)) & 0xFF)) & 0xFF

    return bytes(first8_fixed), bytes(second8)

# ── Const XOR key (mirrors const_xor.c get_const_xor_key) ────────────
# Same SHA-256 IV constants, different Feistel key ordering than oracle
def _const_share0_first():
    """Feistel(c0^c2, c1^c3, keys={c5,c6,c7,c4}) — 8 bytes"""
    c = _KDF_IV
    L = _mba_xor(c[0], c[2])
    R = _mba_xor(c[1], c[3])
    for k in (c[5], c[6], c[7], c[4]):
        tmp = R
        R = _mba_xor(L, _mba_f(R, k))
        L = tmp
    return struct.pack('<II', L, R)

def _const_share0_second():
    """Feistel(c4^c6, c5^c7, keys={c3,c2,c1,c0}) — 8 bytes"""
    c = _KDF_IV
    L = _mba_xor(c[4], c[6])
    R = _mba_xor(c[5], c[7])
    for k in (c[3], c[2], c[1], c[0]):
        tmp = R
        R = _mba_xor(L, _mba_f(R, k))
        L = tmp
    return struct.pack('<II', L, R)

def compute_const_xor_key(so_path=None, soKey=None):
    """Compute const_xor key matching C code in const_xor.c.
    Key = LCG_expand(CRC32(KPT) ^ (IV_A[0] ^ ror13(IV_A[2])) ^ (LE_u32(IV[0:4]) ^ LE_u32(IV2[0:4])))
    All inputs are fixed constants — no dependency on .so or soKey."""
    import zlib as _zlib

    # Piece 0: CRC32 of KPT (24 bytes LE)
    kpt_raw = struct.pack('<6I', 0x00000001, 0x00000002, 0xdeadbeef, 0xcafebabe,
                          0x12345678, 0x9abcdef0)
    piece0 = _zlib.crc32(kpt_raw) & 0xFFFFFFFF

    # Piece 1: IV_A[0] ^ ror13(IV_A[2])
    iv_a2 = 0x8BADF00D
    piece1 = 0xDEADBEEF ^ (((iv_a2 >> 13) | (iv_a2 << 19)) & 0xFFFFFFFF)

    # Piece 2: LE_u32(IV[0:4]) ^ LE_u32(IV2[0:4])
    # IV  = [0x01,0x23,0x45,0x67,...] → LE u32 = 0x67452301
    # IV2 = [0xA5,0x5A,0xC3,0x3C,...] → LE u32 = 0x3CC35AA5
    piece2 = 0x67452301 ^ 0x3CC35AA5

    seed = piece0 ^ piece1 ^ piece2
    key = bytearray(16)
    s = seed
    for i in range(4):
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
        struct.pack_into('<I', key, i * 4, s)
    return bytes(key)

# ── Helper: XOR encrypt a value with the const key ──────────────────
def xor_encrypt_u32(value, key, offset):
    """Encrypt a uint32 with cx_key[offset & 0xF : (offset+4) & 0xF]"""
    k = struct.unpack_from('<I', key, offset & 0xF)[0]
    return (value ^ k) & 0xFFFFFFFF

def xor_encrypt_bytes(data, key):
    """Encrypt a bytearray/bytes with cyclic key."""
    return bytes(data[i] ^ key[i & 0xF] for i in range(len(data)))

def compute_oracle_xor_key(so_path, soKey):
    """计算 3-share oracle XOR key（需要 .so 路径和 soKey）"""
    s0_first = _compute_share0_first()
    s0_second = _compute_share0_second()
    s1_first, s1_second = _compute_share1(so_path)
    s2_first, s2_second = _compute_share2(soKey)

    key = bytearray(16)
    for i in range(8):
        key[i] = s0_first[i] ^ s1_first[i] ^ s2_first[i]
    for i in range(8):
        key[8+i] = s0_second[i] ^ s1_second[i] ^ s2_second[i]

    return bytes(key)

# ORACLE_XOR_KEY 现在是动态计算的，不再是全局常量
# 在 encrypt_oracle_section 中使用 compute_oracle_xor_key(so_path, soKey)


def encrypt_oracle_section(so_path, soKey):
    """XOR-encrypt the oracle shellcode in the .so.
    Also patches the seeds data at the end of the shellcode.
    Returns True if patched, False if section not found."""
    oracle_key = compute_oracle_xor_key(so_path, soKey)
    with open(so_path, "rb") as f:
        data = bytearray(f.read())

    # Parse ELF section headers to find oracle_code_start/end symbols
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]

    # Section name string table
    sh = data[e_shoff + e_shstrndx * e_shentsize:e_shoff + (e_shstrndx + 1) * e_shentsize]
    strtab_off = struct.unpack_from("<Q", sh, 24)[0]
    strtab_size = struct.unpack_from("<Q", sh, 32)[0]
    strtab = data[strtab_off:strtab_off + strtab_size]

    # Find .rodata.oracle section
    oracle_foff = oracle_size = 0
    for i in range(e_shnum):
        sh = data[e_shoff + i * e_shentsize:e_shoff + (i + 1) * e_shentsize]
        ni = struct.unpack_from("<I", sh, 0)[0]
        end = strtab.index(b"\x00", ni)
        name = strtab[ni:end].decode()
        if name == ".rodata.oracle":
            oracle_foff = struct.unpack_from("<Q", sh, 24)[0]
            oracle_size = struct.unpack_from("<Q", sh, 32)[0]
            break

    if oracle_foff == 0:
        # Section might be merged into .rodata by linker — try symbol-based approach
        return _encrypt_oracle_by_symbol(so_path, data, oracle_key)

    # XOR encrypt the entire section
    for i in range(oracle_size):
        data[oracle_foff + i] ^= oracle_key[i & 0x0F]

    with open(so_path, "wb") as f:
        f.write(data)
    log(f"  oracle section XOR-encrypted ({oracle_size} bytes at offset 0x{oracle_foff:x})")
    return True


def _encrypt_oracle_by_symbol(so_path, data, oracle_key):
    """Fallback: find oracle_code_start/end via symbol table and XOR that range."""
    # Use llvm-nm to find symbols
    ndk = os.path.expanduser("~/AppData/Local/Android/Sdk/ndk/27.0.12077973")
    nm = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
    if not os.path.isfile(nm):
        for ndk_dir in ["27.0.12077973", "26.3.11579264", "25.2.9519653"]:
            ndk = os.path.expanduser(f"~/AppData/Local/Android/Sdk/ndk/{ndk_dir}")
            nm = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
            if os.path.isfile(nm):
                break
    if not os.path.isfile(nm):
        log("  WARNING: llvm-nm not found, cannot encrypt oracle section")
        return False

    try:
        out = subprocess.check_output([nm, "--defined-only", so_path], text=True,
                                      encoding="utf-8", errors="replace")
    except Exception:
        log("  WARNING: llvm-nm failed on .so")
        return False

    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)

    start_va = syms.get("oracle_code_start", 0)
    end_va = syms.get("oracle_code_end", 0)
    if not start_va or not end_va or end_va <= start_va:
        log("  WARNING: oracle_code_start/end symbols not found")
        return False

    code_size = end_va - start_va

    # Convert VA to file offset: find the LOAD segment containing this VA
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]

    file_offset = 0
    for i in range(e_phnum):
        ph = data[e_phoff + i * e_phentsize:e_phoff + (i + 1) * e_phentsize]
        p_type = struct.unpack_from("<I", ph, 0)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_offset = struct.unpack_from("<Q", ph, 8)[0]
        p_vaddr = struct.unpack_from("<Q", ph, 16)[0]
        p_filesz = struct.unpack_from("<Q", ph, 32)[0]
        if p_vaddr <= start_va < p_vaddr + p_filesz:
            file_offset = p_offset + (start_va - p_vaddr)
            break

    if file_offset == 0:
        log("  WARNING: could not map oracle VA to file offset")
        return False

    # XOR encrypt
    for i in range(code_size):
        data[file_offset + i] ^= oracle_key[i & 0x0F]

    with open(so_path, "wb") as f:
        f.write(data)
    log(f"  oracle shellcode XOR-encrypted ({code_size} bytes at file offset 0x{file_offset:x})")
    return True


def patch_oracle_material(so_path, material_32):
    """Patch the 32 bytes material[0:32] into the oracle shellcode's .L_material_data.
    Material data is at the end of oracle_code (32 bytes + 4 byte sentinel before oracle_code_end).
    Must be called BEFORE encrypt_oracle_section."""
    with open(so_path, "rb") as f:
        data = bytearray(f.read())

    # Find oracle_code_end symbol to locate material (32+4 bytes before it)
    ndk = os.path.expanduser("~/AppData/Local/Android/Sdk/ndk/27.0.12077973")
    nm = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
    if not os.path.isfile(nm):
        for ndk_dir in ["27.0.12077973", "26.3.11579264", "25.2.9519653"]:
            ndk = os.path.expanduser(f"~/AppData/Local/Android/Sdk/ndk/{ndk_dir}")
            nm = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
            if os.path.isfile(nm):
                break

    try:
        out = subprocess.check_output([nm, "--defined-only", so_path], text=True,
                                      encoding="utf-8", errors="replace")
    except Exception:
        log("  WARNING: cannot patch oracle material (llvm-nm failed)")
        return False

    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)

    end_va = syms.get("oracle_code_end", 0)
    if not end_va:
        log("  WARNING: oracle_code_end symbol not found")
        return False

    # Layout: [.L_material_data: 32 bytes] [oracle_code_end] [sentinel: 4 bytes]
    material_va = end_va - 32

    # VA to file offset
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]

    file_offset = 0
    for i in range(e_phnum):
        ph = data[e_phoff + i * e_phentsize:e_phoff + (i + 1) * e_phentsize]
        p_type = struct.unpack_from("<I", ph, 0)[0]
        if p_type != 1:
            continue
        p_offset = struct.unpack_from("<Q", ph, 8)[0]
        p_vaddr = struct.unpack_from("<Q", ph, 16)[0]
        p_filesz = struct.unpack_from("<Q", ph, 32)[0]
        if p_vaddr <= material_va < p_vaddr + p_filesz:
            file_offset = p_offset + (material_va - p_vaddr)
            break

    if file_offset == 0:
        log("  WARNING: cannot map material VA to file offset")
        return False

    # Write 32 bytes
    data[file_offset:file_offset + 32] = material_32

    with open(so_path, "wb") as f:
        f.write(data)
    log(f"  oracle material[0:32] patched at file offset 0x{file_offset:x}")
    return True


# ── 步骤 3: soKey 派生（读取 .text section）─────────────────────
def derive_sokey(so_path):
    """Read .text section from ELF, compute CRC32, derive soKey."""
    with open(so_path, "rb") as f:
        data = f.read()

    # Section header approach (works on both stripped and unstripped)
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]

    # Get section name string table
    sh = data[e_shoff + e_shstrndx * e_shentsize:e_shoff + (e_shstrndx + 1) * e_shentsize]
    strtab_off = struct.unpack_from("<Q", sh, 24)[0]
    strtab_size = struct.unpack_from("<Q", sh, 32)[0]
    strtab = data[strtab_off:strtab_off + strtab_size]

    text_bytes = None
    text_vaddr = text_foff = text_size = 0
    for i in range(e_shnum):
        sh = data[e_shoff + i * e_shentsize:e_shoff + (i + 1) * e_shentsize]
        ni = struct.unpack_from("<I", sh, 0)[0]
        end = strtab.index(b"\x00", ni)
        name = strtab[ni:end].decode()
        if name == ".text":
            text_foff  = struct.unpack_from("<Q", sh, 24)[0]
            text_vaddr = struct.unpack_from("<Q", sh, 16)[0]
            text_size  = struct.unpack_from("<Q", sh, 32)[0]
            text_bytes = data[text_foff:text_foff + text_size]
            break

    assert text_bytes is not None, ".text section not found"

    crc = zlib.crc32(text_bytes) & 0xFFFFFFFF

    EXPAND = [0xA3F1B28C7D4E5F60, 0x9C8B7A6D5E4F3021,
              0x1F2E3D4C5B6A7980, 0xD0E1F2038495A6B7]
    MUL, ADD, M64 = 0x5851F42D4C957F2D, 0x14057B7EF767814F, (1 << 64) - 1
    key = bytearray(16)
    for i in range(4):
        m = ((crc ^ EXPAND[i]) * MUL + ADD) & M64
        key[i * 4]     = (m >> 24) & 0xFF
        key[i * 4 + 1] = (m >> 16) & 0xFF
        key[i * 4 + 2] = (m >> 8)  & 0xFF
        key[i * 4 + 3] = m & 0xFF
    return bytes(key), crc, data, text_foff, text_vaddr, text_size


# ── 步骤 4: 提取 BB 地址 ─────────────────────────────────────────
def find_core_compute_bounds(data, text_foff, text_vaddr, text_size, so_path):
    """Find core_compute function boundaries using llvm-nm (NDK)."""
    ndk = os.path.expanduser("~/AppData/Local/Android/Sdk/ndk/27.0.12077973")
    nm = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
    if not os.path.isfile(nm):
        # Try finding any NDK version
        for ndk_dir in ["27.0.12077973", "26.3.11579264", "25.2.9519653"]:
            ndk = os.path.expanduser(f"~/AppData/Local/Android/Sdk/ndk/{ndk_dir}")
            nm = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
            if os.path.isfile(nm):
                break
    if not os.path.isfile(nm):
        log("llvm-nm not found, scanning entire .text (may produce wrong BB offsets)")
        return None, None

    try:
        out = subprocess.check_output([nm, "--defined-only", so_path], text=True,
                                      encoding="utf-8", errors="replace")
    except Exception:
        log("llvm-nm failed, scanning entire .text")
        return None, None

    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)

    core_va = syms.get("core_compute", 0)
    if not core_va:
        log("core_compute symbol not found")
        return None, None

    # Find end: next symbol after core_compute
    sorted_vas = sorted(syms.values())
    core_end = core_va + 0x800  # default size
    for v in sorted_vas:
        if v > core_va:
            core_end = v
            break
    return core_va, core_end


def extract_bb_addrs(data, text_foff, text_vaddr, text_size, so_path=None):
    """Scan .text for key instructions in core_compute. Return BB offsets."""
    # Try to limit to core_compute function
    core_start, core_end = None, None
    if so_path:
        core_start, core_end = find_core_compute_bounds(data, text_foff, text_vaddr, text_size, so_path)

    b_insns = []
    tbz_insns = []
    adr_br = []
    dead_blocks = []

    scan_start = core_start if core_start else text_vaddr
    scan_end   = core_end if core_end else (text_vaddr + text_size)

    for off in range(text_foff + (scan_start - text_vaddr),
                     text_foff + (scan_end - text_vaddr), 4):
        insn = struct.unpack_from("<I", data, off)[0]
        va = text_vaddr + (off - text_foff)

        # B instruction
        if (insn >> 26) == 0x05:
            imm26 = insn & 0x03FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            target = (va + imm26 * 4) & 0xFFFFFFFF
            b_insns.append((off - text_foff, target - text_vaddr, insn, va))

        # TBZ/TBNZ
        if (insn >> 24) in (0x36, 0x37):
            imm14 = (insn >> 5) & 0x3FFF
            if imm14 & (1 << 13):
                imm14 -= (1 << 14)
            target = (va + imm14 * 4) & 0xFFFFFFFF
            tbz_insns.append((off - text_foff, (insn >> 19) & 0x1F, target - text_vaddr, insn))

        # ADR + BR (dispatch table jump)
        if (insn & 0x9F000000) == 0x10000000 and (insn >> 31) == 0:
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            target = (va + imm21) & 0xFFFFFFFF
            next_insn = struct.unpack_from("<I", data, off + 4)[0]
            if (next_insn & 0xFFFFFC1F) == 0xD61F0000:
                adr_br.append((off - text_foff, target - text_vaddr, insn))

        # Dead block: mov xn, xn
        if insn in (0xAA0903E9, 0xAA0A03EA, 0xAA0B03EB, 0xAA0C03EC):
            dead_blocks.append(off - text_foff)

    result = {}

    # BB0: first B instruction → BB1
    if b_insns:
        result["BB0_BRANCH_OFF"] = b_insns[0][0]
        result["BB1_OFF"] = b_insns[0][1]

    # BB2: first TBZ → BB3
    if tbz_insns:
        result["BB2_TBZ_OFF"] = tbz_insns[0][0]

    # BB6: ADR+BR → BB7
    if adr_br:
        result["BB6_ADR_OFF"] = adr_br[0][0]
        result["BB7_ENTRY_OFF"] = adr_br[0][1]

    # BB4: B to dead block
    if dead_blocks:
        result["DEAD_BLOCK_OFF"] = dead_blocks[0]
        for off, tgt, _, _ in b_insns:
            if tgt == dead_blocks[0]:
                result["BB4_BRANCH_OFF"] = off
                break
        if "BB4_BRANCH_OFF" not in result:
            for off, tgt, _, _ in reversed(b_insns):
                if off < dead_blocks[0]:
                    result["BB4_BRANCH_OFF"] = off
                    break
        result["BB5_OFF"] = result["DEAD_BLOCK_OFF"] + 16

    return result


# ── 步骤 5: 正向模拟 ────────────────────────────────────────────
def expand_key_material(flag_bytes, out_len=96):
    buf = bytearray(32)
    buf[:25] = flag_bytes
    buf[25:] = bytes([0x5A] * 7)
    s = list(struct.unpack_from("<4Q", buf))
    for r in range(12):
        s[0] = (ror64(s[0], 8) + s[1]) & ((1 << 64) - 1)
        s[0] ^= r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) & ((1 << 64) - 1)
        s[2] ^= (r + 4)
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


def compute_kct_kout(flag_bytes, soKey, bb_addrs):
    """Compute KCT and KOUT pairs for the given flag and soKey."""
    cfg_dep = bb_addrs["BB6_ADR_OFF"] & 0xFF

    # --- repair_sbox ---
    sbox_seed = struct.unpack_from("<I", flag_bytes, 9)[0]
    xs = sbox_seed & 0xFFFFFFFF
    ks = []
    for _ in range(256):
        xs ^= (xs << 13) & 0xFFFFFFFF
        xs ^= (xs >> 17) & 0xFFFFFFFF
        xs ^= (xs << 5)  & 0xFFFFFFFF
        ks.append(xs & 0xFF)
    sbox = [0] * 256
    for i in range(256):
        sbox[(i + cfg_dep) & 0xFF] ^= ks[i]
    sbox_first = sbox[0]

    # --- repair_constants ---
    xtea_delta = struct.unpack_from("<I", flag_bytes, 13)[0]
    lcg_seed = struct.unpack_from("<I", flag_bytes, 17)[0]
    lcg = (lcg_seed ^ (sbox_first * 0x01010101)) & 0xFFFFFFFF
    rc = []
    for _ in range(32):
        lcg = (lcg * 1664525 + 1013904223) & 0xFFFFFFFF
        rc.append(lcg)

    # --- compute KCT (3 XTEA pairs) ---
    def xtea_check(v0, v1):
        da = 0
        for r in range(16):
            da = (da + xtea_delta) & 0xFFFFFFFF
            v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (da + rc[r * 2]))) & 0xFFFFFFFF
            v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (da + rc[r * 2 + 1]))) & 0xFFFFFFFF
        return v0, v1

    KPT = [(0x00000001, 0x00000002),
           (0xDEADBEEF, 0xCAFEBABE),
           (0x12345678, 0x9ABCDEF0)]
    KCT = [xtea_check(a, b) for a, b in KPT]

    # --- repair_semantics ---
    rc_high4 = (rc[0] >> 28) & 0xF
    step3_bits = 16 + rc_high4
    step2_amount = flag_bytes[21] & 0x1F
    raw = flag_bytes[22] | (flag_bytes[23] << 8) | (flag_bytes[24] << 16)
    mask = (1 << step3_bits) - 1 if step3_bits < 32 else 0xFFFFFFFF
    step3_param = raw & mask

    def s3(val, param):
        m = (1 << step3_bits) - 1 if step3_bits < 32 else 0xFFFFFFFF
        param &= m
        return (val ^ (((val >> 5) + param) & 0xFFFFFFFF) ^
                (((val << 4) + (param >> 12)) & 0xFFFFFFFF)) & 0xFFFFFFFF

    def s2(val, amt):
        amt &= 0x1F
        if amt == 0:
            return val
        return ((val << amt) | (val >> (32 - amt))) & 0xFFFFFFFF

    KIN = [0x00000001, 0x12345678, 0xDEADBEEF, 0xCAFEBABE,
           0x8BADF00D, 0xFEEDFACE, 0x01234567, 0x89ABCDEF]
    KOUT = [s2(s3(x, step3_param), step2_amount) for x in KIN]

    # --- EXPECTED_SOKEY_CHECK ---
    mat = bytearray(128)
    mat[:96] = expand_key_material(flag_bytes, 96)
    for i in range(16):
        mat[96 + i] = mat[i] ^ soKey[i]
    rk15 = struct.unpack_from("<I", mat, 60)[0]
    sokey_12_16 = struct.unpack_from("<I", soKey, 12)[0]
    EXPECTED_SOKEY_CHECK = rk15 ^ sokey_12_16

    return KCT, KOUT, rc, sbox, step3_bits, EXPECTED_SOKEY_CHECK


def compute_enc_expected_a(flag_bytes, soKey, bb_addrs, rc, sbox):
    """Forward-simulate scheme A to compute ENC_EXPECTED_STATE_A."""
    xtea_delta = struct.unpack_from("<I", flag_bytes, 13)[0]
    rc_high4 = (rc[0] >> 28) & 0xF
    step3_bits = 16 + rc_high4
    step2_amount = flag_bytes[21] & 0x1F
    raw = flag_bytes[22] | (flag_bytes[23] << 8) | (flag_bytes[24] << 16)
    mask = (1 << step3_bits) - 1 if step3_bits < 32 else 0xFFFFFFFF
    step3_param = raw & mask
    IV_A = [0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE]

    def rol32(v, n):
        n &= 31
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    def step3_fn(sv, param):
        m = (1 << step3_bits) - 1 if step3_bits < 32 else 0xFFFFFFFF
        param &= m
        return (sv ^ (((sv >> 5) + param) & 0xFFFFFFFF) ^
                (((sv << 4) + (param >> 12)) & 0xFFFFFFFF)) & 0xFFFFFFFF

    def xtea_rnd(v0, v1, rc_val, da):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (da + rc_val))) & 0xFFFFFFFF
        t  = rol32(v0, step2_amount)
        v1 = (v1 + (step3_fn(t, rc_val) ^ (da + rc_val))) & 0xFFFFFFFF
        return v0, v1

    v0 = IV_A[0] ^ 0
    v1 = IV_A[1] ^ 0
    v2 = IV_A[2] ^ 0
    v3 = IV_A[3] ^ 0
    da = 0

    for bb in range(7):
        da = (da + xtea_delta) & 0xFFFFFFFF
        v0, v1 = xtea_rnd(v0, v1, rc[bb * 2],     da)
        v2, v3 = xtea_rnd(v2, v3, rc[bb * 2 + 1], da)

    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[14], da)
    v2, v3 = xtea_rnd(v2, v3, rc[15], da)
    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[16], da)
    v2, v3 = xtea_rnd(v2, v3, rc[17], da)
    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[18], da)
    v2, v3 = xtea_rnd(v2, v3, rc[19], da)

    v0 ^= sbox[v0 & 0xFF]
    v1 ^= sbox[v1 & 0xFF]
    v2 ^= sbox[v2 & 0xFF]
    v3 ^= sbox[v3 & 0xFF]

    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[20], da)
    v2, v3 = xtea_rnd(v2, v3, rc[21], da)
    da = (da + xtea_delta) & 0xFFFFFFFF
    v0, v1 = xtea_rnd(v0, v1, rc[22], da)
    v2, v3 = xtea_rnd(v2, v3, rc[23], da)

    final = bytes(
        struct.pack("<IIII", v0, v1, v2, v3)
    )
    return bytes(final[i] ^ soKey[i] for i in range(16))


def compute_enc_expected_b(flag_bytes, soKey, expected_check, iv=None):
    """Forward-simulate scheme B to compute ENC_EXPECTED_STATE."""
    if iv is None:
        iv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
              0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]

    mat = bytearray(128)
    mat[:96] = expand_key_material(flag_bytes, 96)
    for i in range(16):
        mat[96 + i] = mat[i] ^ soKey[i]
    for i in range(16):
        mat[112 + i] = mat[32 + i]  # IPC fallback (all zero)

    rk = [struct.unpack_from("<I", mat, i * 4)[0] for i in range(16)]
    cfgs = []
    for i in range(16):
        b = mat[64 + i]
        cfgs.append({"ss": (b >> 0) & 3, "sp": (b >> 2) & 3,
                     "mm": (b >> 4) & 3, "nm": (b >> 6) & 3})
    seeds = [struct.unpack_from("<I", mat, 80 + i * 4)[0] for i in range(4)]
    delta = struct.unpack_from("<I", mat, 96)[0]

    check = rk[15] ^ struct.unpack_from("<I", soKey, 12)[0]
    diff = check ^ expected_check
    poison = (((diff | ((~diff + 1) & 0xFFFFFFFF)) >> 31) & 1) * 0xDEADBEEF
    delta ^= poison

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

    sboxes = [generate_sbox(s) for s in seeds]

    MDS = [
        [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]],
        [[5, 3, 4, 2], [2, 5, 3, 4], [4, 2, 5, 3], [3, 4, 2, 5]],
        [[7, 6, 2, 3], [3, 7, 6, 2], [2, 3, 7, 6], [6, 2, 3, 7]],
        [[9, 14, 5, 4], [4, 9, 14, 5], [5, 4, 9, 14], [14, 5, 4, 9]],
    ]
    SHIFTS = [[0, 1, 2, 3], [0, 1, 3, 4], [0, 2, 3, 1], [0, 3, 1, 2]]
    NL_POWER = [7, 11, 13, 23]

    state = list(iv)
    state_crc_mix = 0
    for rnd in range(16):
        if rnd == 8:
            state_crc_mix = _crc32_16(bytes(state))
        dyn_key = rk[rnd]
        if rnd >= 8:
            dyn_key ^= struct.unpack_from("<I", bytes(state[:4]))[0]
            dyn_key ^= state_crc_mix
        sel = cfgs[rnd]["ss"] if rnd < 8 else (cfgs[rnd]["ss"] ^ state[0]) & 3
        state = [sboxes[sel][b] for b in state]
        tmp = state[:]
        for row in range(4):
            s = SHIFTS[cfgs[rnd]["sp"]][row] & 3
            for col in range(4):
                state[row + 4 * col] = tmp[row + 4 * ((col + s) % 4)]
        res = [0] * 16
        for col in range(4):
            inp = state[col * 4:col * 4 + 4]
            m = MDS[cfgs[rnd]["mm"]]
            for i in range(4):
                v = 0
                for j in range(4): v ^= gf_mul(m[i][j], inp[j])
                res[col * 4 + i] = v
        state = res
        power = NL_POWER[cfgs[rnd]["nm"] & 3]
        rc_byte = (delta >> ((rnd % 4) * 8)) & 0xFF
        state = [gf_pow(b ^ rc_byte ^ (rnd & 0xFF), power) for b in state]
        k = struct.pack("<I", dyn_key)
        state = [state[i] ^ k[i % 4] for i in range(16)]

    final = bytes(state)
    return bytes(final[i] ^ soKey[i] for i in range(16))


# ── 步骤 6: 组装 flag ────────────────────────────────────────────
def build_flag(soKey, bb_addrs):
    """Build flag bytes from BB addresses and soKey."""
    BB0_BRANCH_OFF = bb_addrs["BB0_BRANCH_OFF"]
    BB6_ADR_OFF    = bb_addrs["BB6_ADR_OFF"]
    DEAD_OFF       = bb_addrs.get("DEAD_BLOCK_OFF", 0)
    BB4_BRANCH_OFF = bb_addrs.get("BB4_BRANCH_OFF", 0)

    flag = bytearray(25)

    # flag[0:4] = BB0 B imm26 XOR key → fix BB0 jump to BB1
    correct_imm26 = (bb_addrs["BB1_OFF"] - BB0_BRANCH_OFF) // 4
    struct.pack_into("<I", flag, 0, correct_imm26 & 0x03FFFFFF)

    # flag[4] = TBZ bit field XOR (set to 1 to test bit 1 not 0)
    flag[4] = 0x01

    # flag[5:9] ^ soKey[8:12] == (BB5-DEAD)/4 ^ (DEAD-BB4)/4
    DEAD_OFF = bb_addrs.get("DEAD_BLOCK_OFF", 0)
    BB4_BRANCH_OFF = bb_addrs.get("BB4_BRANCH_OFF", 0)
    BB5_OFF_V = bb_addrs.get("BB5_OFF", DEAD_OFF + 16)
    if BB4_BRANCH_OFF and DEAD_OFF:
        expected_b4 = ((BB5_OFF_V - DEAD_OFF) // 4) ^ ((DEAD_OFF - BB4_BRANCH_OFF) // 4)
    else:
        expected_b4 = 5  # fallback
    sokey_8_11 = struct.unpack_from("<I", soKey, 8)[0]
    flag_5_8 = (expected_b4 ^ sokey_8_11) & 0xFFFFFFFF
    struct.pack_into("<I", flag, 5, flag_5_8)

    # flag[9:13] = ADR imm21 XOR key with soKey[0:4]
    # adr_key = flag[9:12] ^ soKey[0:4] must encode imm21 = BB7_ENTRY_OFF - BB6_ADR_OFF
    sokey_0_3 = struct.unpack_from("<I", soKey, 0)[0]
    bb6 = bb_addrs["BB6_ADR_OFF"]
    bb7 = bb_addrs["BB7_ENTRY_OFF"]
    imm21 = bb7 - bb6
    # adr encoding: immlo = imm21[1:0] at bits[30:29], immhi = imm21[20:2] at bits[23:5]
    adr_bits = ((imm21 & 0x3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5)
    flag_9_12 = (sokey_0_3 ^ adr_bits) & 0xFFFFFFFF
    struct.pack_into("<I", flag, 9, flag_9_12)

    # flag[13:17] = XTEA delta
    struct.pack_into("<I", flag, 13, 0x9E3779B9)

    # flag[17:21] = LCG seed
    struct.pack_into("<I", flag, 17, 0xDEADC0DE)

    # flag[21] = step2 amount
    flag[21] = 7

    # flag[22:25] = step3 param
    flag[22] = 0x42
    flag[23] = 0x13
    flag[24] = 0x37

    return bytes(flag)


# ── 步骤 7: 更新源文件 ───────────────────────────────────────────
def update_file(path, old, new, multiline=False):
    """Replace old→new in file. Return True if changed."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if multiline:
        if new in content:
            return False
        # Use regex replace
        new_content = re.sub(old, new, content, flags=re.DOTALL)
    else:
        new_content = content.replace(old, new)
    if new_content == content:
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_content)
    return True


def fmt_hex_row(data):
    """Format bytes as two rows of 8 for C array initialization."""
    parts = [f"0x{b:02X}" for b in data]
    return ", ".join(parts[:8]) + ",\n    " + ", ".join(parts[8:])


def update_all_files(enc_a, enc_b, enc_b2, KCT, KOUT, EXPECTED_SOKEY_CHECK, crc, flag_b64_a, sbox_check, bb_addrs=None, so_path=None):
    """Write all computed constants back to source files (XOR-encrypted)."""
    # Compute XOR key for constant protection (fixed derivation, no .so dependency)
    cx_key = compute_const_xor_key()

    enc_a_enc = xor_encrypt_bytes(enc_a, cx_key)
    enc_b_enc = xor_encrypt_bytes(enc_b, cx_key)
    enc_b2_enc = xor_encrypt_bytes(enc_b2, cx_key)
    enc_a_str = fmt_hex_row(enc_a_enc)
    enc_b_str = fmt_hex_row(enc_b_enc)
    enc_b2_str = fmt_hex_row(enc_b2_enc)

    changes = 0

    # --- repair_constants.c: KCT_ENC array (XOR encrypted) ---
    src = os.path.join(ROOT, "app/src/main/cpp/src/repair_constants.c")
    kct_enc = [[xor_encrypt_u32(KCT[i][j], cx_key, i * 8 + j * 4) for j in range(2)] for i in range(3)]
    new_kct = (
        f"static volatile const uint32_t KCT_ENC[3][2] = {{\n"
        f"    {{{kct_enc[0][0]:#010x}u, {kct_enc[0][1]:#010x}u}},\n"
        f"    {{{kct_enc[1][0]:#010x}u, {kct_enc[1][1]:#010x}u}},\n"
        f"    {{{kct_enc[2][0]:#010x}u, {kct_enc[2][1]:#010x}u}}\n"
        f"}};"
    )
    if update_file(src, r"static volatile const uint32_t KCT_ENC\[3\]\[2\] = \{[^;]+;", new_kct, multiline=True):
        changes += 1
        log(f"  update repair_constants.c (KCT_ENC)")

    # --- repair_semantics.c: KOUT_ENC array (XOR encrypted) ---
    src = os.path.join(ROOT, "app/src/main/cpp/src/repair_semantics.c")
    kout_enc = [xor_encrypt_u32(KOUT[i], cx_key, i * 4) for i in range(8)]
    kout_parts_enc = [f"{v:#010x}u" for v in kout_enc[:4]] + [f"{v:#010x}u" for v in kout_enc[4:]]
    new_kout = f"static volatile const uint32_t KOUT_ENC[8] = {{\n    {', '.join(kout_parts_enc[:4])},\n    {', '.join(kout_parts_enc[4:])}\n}};"
    if update_file(src, r"static volatile const uint32_t KOUT_ENC\[8\] = \{[^;]+;", new_kout, multiline=True):
        changes += 1
        log(f"  update repair_semantics.c (KOUT_ENC)")

    # --- key_expand.c: EXPECTED_SOKEY_CHECK_ENC (XOR encrypted) ---
    src = os.path.join(ROOT, "app/src/main/cpp/src/key_expand.c")
    expected_enc = xor_encrypt_u32(EXPECTED_SOKEY_CHECK, cx_key, 0)
    pattern = r"EXPECTED_SOKEY_CHECK_ENC = 0x[0-9a-fA-F]+u;"
    repl = f"EXPECTED_SOKEY_CHECK_ENC = {expected_enc:#010x}u;"
    if update_file(src, pattern, repl, multiline=True):
        changes += 1
        log(f"  update key_expand.c (EXPECTED_SOKEY_CHECK_ENC={expected_enc:#010x}u)")

    # --- jni_entry.c: ENC_EXPECTED_STATE_ENC arrays (XOR encrypted) ---
    src = os.path.join(ROOT, "app/src/main/cpp/src/jni_entry.c")
    with open(src, "r", encoding="utf-8") as f:
        content = f.read()

    # Update ENC_EXPECTED_STATE_ENC (scheme B, first)
    new_content = re.sub(
        r"(volatile const uint8_t ENC_EXPECTED_STATE_ENC\[STATE_LEN\] = \{)\s*\n\s*[^\n]+\n\s*[^\n]+\n(\s*\};)",
        lambda m: m.group(1) + "\n    " + enc_b_str + "\n" + m.group(2),
        content, count=1
    )

    # Update ENC_EXPECTED_STATE_A_ENC (scheme A)
    new_content = re.sub(
        r"(volatile const uint8_t ENC_EXPECTED_STATE_A_ENC\[STATE_LEN\] = \{)\s*\n\s*[^\n]+\n\s*[^\n]+\n(\s*\};)",
        lambda m: m.group(1) + "\n    " + enc_a_str + "\n" + m.group(2),
        new_content, count=1
    )

    # Update ENC_EXPECTED_STATE2_ENC (scheme B, second)
    new_content = re.sub(
        r"(volatile const uint8_t ENC_EXPECTED_STATE2_ENC\[STATE_LEN\] = \{)\s*\n\s*[^\n]+\n\s*[^\n]+\n(\s*\};)",
        lambda m: m.group(1) + "\n    " + enc_b2_str + "\n" + m.group(2),
        new_content, count=1
    )

    if new_content != content:
        with open(src, "w", encoding="utf-8") as f:
            f.write(new_content)
        changes += 1
        log(f"  update jni_entry.c (ENC arrays)")

    # --- repair_sbox.c: SBOX_CHECK_ENC (XOR encrypted) ---
    src = os.path.join(ROOT, "app/src/main/cpp/src/repair_sbox.c")
    sbc_enc = [sbox_check[i] ^ cx_key[i & 0xF] for i in range(3)]
    new_sbox_check = (
        f"static volatile const uint8_t SBOX_CHECK_ENC[3] = "
        f"{{{sbc_enc[0]:#04x}, {sbc_enc[1]:#04x}, {sbc_enc[2]:#04x}}};"
    )
    if update_file(src,
                   r"static volatile const uint8_t SBOX_CHECK_ENC\[3\] = \{[^;]+;",
                   new_sbox_check, multiline=True):
        changes += 1
        log(f"  update repair_sbox.c (SBOX_CHECK_ENC)")

    # --- repair_cfg.c: BB offsets (volatile const → .rodata) ---
    if bb_addrs:
        src = os.path.join(ROOT, "app/src/main/cpp/src/repair_cfg.c")
        bb0 = bb_addrs.get("BB0_BRANCH_OFF", 0)
        bb1 = bb_addrs.get("BB1_OFF", 0)
        bb6 = bb_addrs.get("BB6_ADR_OFF", 0)
        bb7 = bb_addrs.get("BB7_ENTRY_OFF", 0)
        with open(src, "r", encoding="utf-8") as f:
            content = f.read()
        new_content = re.sub(
            r"static volatile const uint32_t BB0_BRANCH_OFF = 0x[0-9a-fA-F]+u;",
            f"static volatile const uint32_t BB0_BRANCH_OFF = 0x{bb0:04x}u;", content)
        new_content = re.sub(
            r"static volatile const uint32_t BB1_OFF\s+= 0x[0-9a-fA-F]+u;",
            f"static volatile const uint32_t BB1_OFF        = 0x{bb1:04x}u;", new_content)
        new_content = re.sub(
            r"static volatile const uint32_t BB6_ADR_OFF_V\s+= 0x[0-9a-fA-F]+u;",
            f"static volatile const uint32_t BB6_ADR_OFF_V  = 0x{bb6:04x}u;", new_content)
        new_content = re.sub(
            r"static volatile const uint32_t BB7_ENTRY_OFF\s+= 0x[0-9a-fA-F]+u;",
            f"static volatile const uint32_t BB7_ENTRY_OFF  = 0x{bb7:04x}u;", new_content)
        bb4 = bb_addrs.get("BB4_BRANCH_OFF", 0)
        bb5 = bb_addrs.get("BB5_OFF", 0)
        dead = bb_addrs.get("DEAD_BLOCK_OFF", 0)
        new_content = re.sub(
            r"static volatile const uint32_t BB4_BRANCH_OFF = 0x[0-9a-fA-F]+u;",
            f"static volatile const uint32_t BB4_BRANCH_OFF = 0x{bb4:04x}u;", new_content)
        new_content = re.sub(
            r"static volatile const uint32_t BB5_OFF\s+= 0x[0-9a-fA-F]+u;",
            f"static volatile const uint32_t BB5_OFF        = 0x{bb5:04x}u;", new_content)
        new_content = re.sub(
            r"static volatile const uint32_t DEAD_BLOCK_OFF = 0x[0-9a-fA-F]+u;",
            f"static volatile const uint32_t DEAD_BLOCK_OFF = 0x{dead:04x}u;", new_content)
        if new_content != content:
            with open(src, "w", encoding="utf-8") as f:
                f.write(new_content)
            changes += 1
            log(f"  update repair_cfg.c (BB0=0x{bb0:04x} BB1=0x{bb1:04x} BB6=0x{bb6:04x} BB7=0x{bb7:04x})")

    return changes


# ── 步骤 8: 验证 ─────────────────────────────────────────────────
def verify_python(so_path, soKey, expected_sokey_check, enc_a, enc_b, enc_b2, bb_addrs):
    """Run Python-side verification of both schemes."""
    flag_b = FLAG_B
    flag_a = build_flag(soKey, bb_addrs)

    log("Verifying scheme B...")
    enc_out_b = compute_enc_expected_b(flag_b, soKey, expected_sokey_check)
    ok_b = (enc_out_b == enc_b)
    log(f"  Scheme B correct flag (IV1): {'PASS' if ok_b else 'FAIL'}")

    enc_out_b2 = compute_enc_expected_b(flag_b, soKey, expected_sokey_check, iv=IV2_B)
    ok_b2 = (enc_out_b2 == enc_b2)
    log(f"  Scheme B correct flag (IV2): {'PASS' if ok_b2 else 'FAIL'}")

    enc_wrong = compute_enc_expected_b(b"\x00" * 25, soKey, expected_sokey_check)
    ok_bad = (enc_wrong != enc_b)
    log(f"  Scheme B wrong flag: {'PASS' if ok_bad else 'FAIL'}")

    enc_bad_key = compute_enc_expected_b(flag_b, b"\x00" * 16, expected_sokey_check)
    ok_bk = (enc_bad_key != enc_b)
    log(f"  Scheme B wrong soKey: {'PASS' if ok_bk else 'FAIL'}")

    b_pass = ok_b and ok_b2 and ok_bad and ok_bk

    log("Verifying scheme A...")
    rc, sbox = None, None
    # Re-run computation
    cfg_dep = bb_addrs["BB6_ADR_OFF"] & 0xFF
    sbox_seed = struct.unpack_from("<I", flag_a, 9)[0]
    xs = sbox_seed & 0xFFFFFFFF
    ks = []
    for _ in range(256):
        xs ^= (xs << 13) & 0xFFFFFFFF
        xs ^= (xs >> 17) & 0xFFFFFFFF
        xs ^= (xs << 5) & 0xFFFFFFFF
        ks.append(xs & 0xFF)
    sbox = [0] * 256
    for i in range(256):
        sbox[(i + cfg_dep) & 0xFF] ^= ks[i]
    lcg_seed = struct.unpack_from("<I", flag_a, 17)[0]
    sbox_first = sbox[0]
    lcg = (lcg_seed ^ (sbox_first * 0x01010101)) & 0xFFFFFFFF
    rc = []
    for _ in range(32):
        lcg = (lcg * 1664525 + 1013904223) & 0xFFFFFFFF
        rc.append(lcg)

    enc_out_a = compute_enc_expected_a(flag_a, soKey, bb_addrs, rc, sbox)
    ok_a = (enc_out_a == enc_a)
    log(f"  Scheme A correct flag: {'PASS' if ok_a else 'FAIL'}")

    enc_aw = compute_enc_expected_a(b"\x00" * 25, soKey, bb_addrs, rc, sbox)
    ok_aw = (enc_aw != enc_a)
    log(f"  Scheme A wrong flag: {'PASS' if ok_aw else 'FAIL'}")

    a_pass = ok_a and ok_aw

    # Interleaved
    log("Verifying 50-byte interleaved flag...")
    inter = bytearray(50)
    for i in range(25):
        inter[i * 2]     = flag_a[i]
        inter[i * 2 + 1] = flag_b[i]
    inter = bytes(inter)
    log(f"  Interleaved flag b64: {base64.b64encode(inter).decode()}")

    return b_pass, a_pass, flag_a


# ═══════════════════════════════════════════════════════════════════
#  主流程
# ═══════════════════════════════════════════════════════════════════
def main():
    log("=" * 50)
    log(f"Convergence ({BUILD_TYPE} build, max {args.max_iter} iterations)")
    log("=" * 50)

    # Build once first
    if not build():
        sys.exit(1)

    prev_crc = None
    for iteration in range(1, args.max_iter + 1):
        so_path = find_so()
        log(f"Iter {iteration}: loading .so -> {os.path.basename(so_path)}")
        soKey, crc, elf_data, text_foff, text_vaddr, text_size = derive_sokey(so_path)
        log(f"  CRC32(.text) = {crc:08x}")
        log(f"  soKey        = {soKey.hex()}")
        so_path_full = so_path

        if crc == prev_crc:
            log(f"  Converged! CRC stable at {crc:08x}")
            break

        prev_crc = crc

        global bb_addrs
        bb_addrs = extract_bb_addrs(elf_data, text_foff, text_vaddr, text_size, so_path)
        log(f"  BB0_BRANCH={bb_addrs.get('BB0_BRANCH_OFF', 0):#06x} "
            f"BB6_ADR={bb_addrs.get('BB6_ADR_OFF', 0):#06x}")

        flag_a = build_flag(soKey, bb_addrs)
        flag_b = FLAG_B

        KCT, KOUT, rc, sbox, step3_bits, _ = \
            compute_kct_kout(flag_a, soKey, bb_addrs)
        # EXPECTED_SOKEY_CHECK 必须从 flag_b 计算（key_schedule 在 verify_scheme_b 中调用）
        mat_b = expand_key_material(flag_b, 96)
        rk15_b = struct.unpack_from("<I", mat_b, 60)[0]
        sokey_12 = struct.unpack_from("<I", soKey, 12)[0]
        EXPECTED_SOKEY_CHECK = rk15_b ^ sokey_12
        log(f"  step3_bits = {step3_bits}")
        log(f"  SOKEY_CHECK = {EXPECTED_SOKEY_CHECK:#010x}")

        enc_a = compute_enc_expected_a(flag_a, soKey, bb_addrs, rc, sbox)
        enc_b = compute_enc_expected_b(flag_b, soKey, EXPECTED_SOKEY_CHECK)
        enc_b2 = compute_enc_expected_b(flag_b, soKey, EXPECTED_SOKEY_CHECK, iv=IV2_B)
        sbox_check = bytes(sbox[0:3])
        log(f"  ENC_A = {enc_a.hex()}")
        log(f"  ENC_B = {enc_b.hex()}")
        log(f"  ENC_B2 = {enc_b2.hex()}")
        log(f"  SBOX_CHECK = {sbox_check.hex()}")

        if args.dry_run:
            log("  [dry-run] skipping file update and rebuild")
            continue

        changes = update_all_files(enc_a, enc_b, enc_b2, KCT, KOUT,
                                   EXPECTED_SOKEY_CHECK, crc,
                                   base64.b64encode(flag_a).decode(), sbox_check, bb_addrs,
                                   so_path)
        if changes == 0:
            log(f"  No file changes, converged")
            break

        if not build():
            sys.exit(1)
    else:
        log(f"WARNING: Did not converge in {args.max_iter} iterations")
        sys.exit(1)

    # ── 收敛后验证 ──────────────────────────────────────────────
    log("=" * 50)
    log("Convergence done, running verification...")
    log("=" * 50)

    so_path = find_so()
    soKey, crc, elf_data, text_foff, text_vaddr, text_size = derive_sokey(so_path)
    bb_addrs = extract_bb_addrs(elf_data, text_foff, text_vaddr, text_size, so_path)
    flag_a = build_flag(soKey, bb_addrs)

    _, _, rc, sbox, _, _ = compute_kct_kout(flag_a, soKey, bb_addrs)
    # EXPECTED_SOKEY_CHECK from flag_b (matches key_schedule in verify_scheme_b)
    mat_b = expand_key_material(FLAG_B, 96)
    rk15_b = struct.unpack_from("<I", mat_b, 60)[0]
    sokey_12 = struct.unpack_from("<I", soKey, 12)[0]
    EXPECTED_SOKEY_CHECK = rk15_b ^ sokey_12
    enc_a = compute_enc_expected_a(flag_a, soKey, bb_addrs, rc, sbox)
    enc_b = compute_enc_expected_b(FLAG_B, soKey, EXPECTED_SOKEY_CHECK)
    enc_b2 = compute_enc_expected_b(FLAG_B, soKey, EXPECTED_SOKEY_CHECK, iv=IV2_B)

    # ── Oracle shellcode 后处理：patch data + XOR encrypt ──────
    log("Patching oracle shellcode...")
    # 计算正确的 oracle 数据: seeds[16] + material[0:16]
    full_mat = expand_key_material(FLAG_B, 96)
    oracle_seeds = full_mat[80:96]    # material[80:96] = seeds
    oracle_mat16 = full_mat[0:16]     # material[0:16] = round_keys[0:4]
    oracle_data = oracle_seeds + oracle_mat16  # 32 bytes total
    log(f"  seeds = {oracle_seeds.hex()}")
    log(f"  material[0:16] = {oracle_mat16.hex()}")

    # Patch 32 bytes 到 .so（明文状态）
    patch_oracle_material(so_path, oracle_data)
    # XOR 加密整个 oracle shellcode 区间
    encrypt_oracle_section(so_path, soKey)

    # ── 重新打包 APK（直接修改 APK 中的 .so，绕过 gradle 缓存问题）──
    log("Patching APK .so directly...")
    apk_path = os.path.join(ROOT, "app/build/outputs/apk", BUILD_TYPE, f"app-{BUILD_TYPE}.apk")
    import zipfile as _zf, shutil as _sh, tempfile as _tf

    # 读取 patched merged .so（已含 oracle data + encryption）
    with open(so_path, "rb") as f:
        patched_so = f.read()

    # Strip the patched .so ourselves using llvm-strip
    ndk = os.path.expanduser("~/AppData/Local/Android/Sdk/ndk/27.0.12077973")
    strip_bin = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-strip.exe"
    if not os.path.isfile(strip_bin):
        for ndk_dir in ["27.0.12077973", "26.3.11579264", "25.2.9519653"]:
            ndk = os.path.expanduser(f"~/AppData/Local/Android/Sdk/ndk/{ndk_dir}")
            strip_bin = f"{ndk}/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-strip.exe"
            if os.path.isfile(strip_bin):
                break

    # Write patched .so to temp, strip it
    tmp_so = os.path.join(ROOT, "app/build/tmp_patched_kctf.so")
    with open(tmp_so, "wb") as f:
        f.write(patched_so)
    subprocess.run([strip_bin, "--strip-unneeded", tmp_so], check=True)
    with open(tmp_so, "rb") as f:
        stripped_patched = f.read()
    os.remove(tmp_so)

    # Replace .so inside APK zip
    tmp_apk = apk_path + ".tmp"
    with _zf.ZipFile(apk_path, 'r') as zin, _zf.ZipFile(tmp_apk, 'w') as zout:
        for item in zin.infolist():
            if item.filename == 'lib/arm64-v8a/libkctf.so':
                zout.writestr(item, stripped_patched)
            else:
                zout.writestr(item, zin.read(item.filename))
    os.replace(tmp_apk, apk_path)

    # Re-sign APK (zip modification invalidates existing signature)
    apksigner = None
    sdk = os.path.expanduser("~/AppData/Local/Android/Sdk")
    import glob as _glob2
    candidates = _glob2.glob(os.path.join(sdk, "build-tools/*/apksigner.bat"))
    if candidates:
        apksigner = sorted(candidates)[-1]
    ks = os.path.expanduser("~/.android/debug.keystore")
    if apksigner and os.path.exists(ks):
        subprocess.run([apksigner, "sign", "--ks", ks, "--ks-pass", "pass:android",
                       "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android",
                       apk_path], check=True, capture_output=True)
        log(f"APK signed: {apk_path}")
    else:
        log(f"WARNING: apksigner not found, APK unsigned!")

    log(f"APK patched: {apk_path} (oracle data injected)")

    b_pass, a_pass, _ = verify_python(so_path, soKey, EXPECTED_SOKEY_CHECK, enc_a, enc_b, enc_b2, bb_addrs)

    log("=" * 50)
    if b_pass and a_pass:
        log("ALL PASS!")
    else:
        log("VERIFICATION FAILED! Check logs")
        sys.exit(1)
    log("=" * 50)

    flag_b = FLAG_B
    inter = bytearray(50)
    for i in range(25):
        inter[i * 2]     = flag_a[i]
        inter[i * 2 + 1] = flag_b[i]

    log(f"Scheme A flag (hex): {flag_a.hex()}")
    log(f"Scheme B flag (hex): {flag_b.hex()}")
    log(f"50-byte flag  (hex): {bytes(inter).hex()}")
    log(f"CRC32(.text) = {crc:08x}")

    # ── 同步 verify.py 中的硬编码常量 ─────────────────────────────
    verify_path = os.path.join(ROOT, "verify.py")
    if os.path.exists(verify_path):
        with open(verify_path, "r", encoding="utf-8") as f:
            vc = f.read()
        changed = False

        # ENC_B
        enc_b_py = "bytes([" + ",".join(f"0x{b:02x}" for b in enc_b) + "])"
        vc, n = re.subn(r"ENC_B\s*=\s*bytes\(\[[^\]]+\]\)", f"ENC_B  = {enc_b_py}", vc)
        if n: changed = True

        # EXPECTED_SOKEY_CHECK
        vc, n = re.subn(r"EXPECTED_SOKEY_CHECK\s*=\s*0x[0-9a-fA-F]+",
                        f"EXPECTED_SOKEY_CHECK = 0x{EXPECTED_SOKEY_CHECK:08x}", vc)
        if n: changed = True

        # FLAG_A
        flag_a_b64 = base64.b64encode(flag_a).decode()
        vc, n = re.subn(r'FLAG_A\s*=\s*base64\.b64decode\("[^"]+"\)',
                        f'FLAG_A = base64.b64decode("{flag_a_b64}")', vc)
        if n: changed = True

        # ENC_A
        enc_a_py = "bytes([" + ",".join(f"0x{b:02x}" for b in enc_a) + "])"
        vc, n = re.subn(r"ENC_A\s*=\s*bytes\(\[[^\]]+\]\)", f"ENC_A  = {enc_a_py}", vc)
        if n: changed = True

        # BB6_ADR_OFF
        vc, n = re.subn(r"BB6_ADR_OFF\s*=\s*0x[0-9a-fA-F]+",
                        f"BB6_ADR_OFF = 0x{bb_addrs['BB6_ADR_OFF']:04x}", vc)
        if n: changed = True

        if changed:
            with open(verify_path, "w", encoding="utf-8") as f:
                f.write(vc)
            log("[autoctf] verify.py constants synced")


if __name__ == "__main__":
    main()
