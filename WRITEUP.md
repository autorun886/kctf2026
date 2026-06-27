# 2026 KCTF 逆向题 WriteUp

## 0x00 概述

Android ARM64 逆向题，输入 100 个 hex 字符（50 字节），程序验证后弹 Toast。

拿到 APK 后解压得到 `lib/arm64-v8a/libkctf.so`，IDA 打开开干。

## 0x01 Java 层

反编译 `MainActivity`，关键逻辑：

```java
byte[] flagBytes = hexDecode(input);  // 100 hex chars → 50 bytes
int result = nativeProcessInput(flagBytes);
if (result == 1) → "Correct!"
```

另有 `deriveNativeKey()` 被 native 通过 JNI 回调：从 APK 中读取 libkctf.so 的 `.text` section，算 CRC32，LCG 扩展为 16 字节 `soKey`。这个 soKey 贯穿整个验证。

Python 复刻：

```python
import zlib, struct, zipfile

so = zipfile.ZipFile('app.apk').read('lib/arm64-v8a/libkctf.so')
# 解析 ELF section headers 找 .text offset/size
text_crc = zlib.crc32(so[text_off:text_off+text_size]) & 0xFFFFFFFF

EXPAND = [0xA3F1B28C7D4E5F60, 0x9C8B7A6D5E4F3021,
          0x1F2E3D4C5B6A7980, 0xD0E1F2038495A6B7]
MUL, ADD = 0x5851F42D4C957F2D, 0x14057B7EF767814F
soKey = bytearray(16)
for i in range(4):
    m = ((text_crc ^ EXPAND[i]) * MUL + ADD) & ((1<<64)-1)
    soKey[i*4:i*4+4] = bytes([(m>>24)&0xFF,(m>>16)&0xFF,(m>>8)&0xFF,m&0xFF])
```

## 0x02 Native 入口分析

`nativeProcessInput` 做了三件事：
1. 50 字节按奇偶拆分：`flagA[25]`（偶数位）、`flagB[25]`（奇数位）
2. 先验证方案 A（`verify_scheme_a`），不通过直接返回 0
3. 再验证方案 B（`verify_scheme_b`），不通过返回 0

两个都过了才返回 1。

## 0x03 方案 B 逆向

### 密钥扩展（ARX）

`expand_key_material(flagB, material, 96)` 把 25 字节 flag 扩展为 96 字节：

```python
def expand_key_material(flag25):
    buf = flag25 + b'\x5A' * 7  # pad to 32
    s = list(struct.unpack('<4Q', buf))  # 4 个 uint64
    
    for r in range(12):  # 12 轮 ARX (Speck 变体)
        s[0] = (ror64(s[0], 8) + s[1]) ^ r
        s[1] = rol64(s[1], 3) ^ s[0]
        s[2] = (ror64(s[2], 8) + s[3]) ^ (r + 4)
        s[3] = rol64(s[3], 3) ^ s[2]
        s[0] ^= s[3]; s[2] ^= s[1]  # cross-mix
    
    # squeeze 3 轮，每轮输出 32 字节
    out = b''
    while len(out) < 96:
        out += struct.pack('<4Q', *s)[:min(32, 96-len(out))]
        s[0] = (s[0] + s[2]) & MASK64
        s[1] ^= s[3]
        s[2] = rol64(s[2], 17)
        s[3] = ror64(s[3], 11)
    return out[:96]
```

material 布局：
- `[0:64]` → 16 个 round_keys (每 4 字节 LE)
- `[64:80]` → 16 个 config 字节 (ss/sp/mm/nm 各 2 bit)
- `[80:96]` → 4 个 sbox_seeds (uint32 LE)

### Oracle：获取约束数据

`verify_scheme_b` 中调用了 `get_oracle_material()`，通过 mmap+XOR 解密执行一段 ARM64 shellcode，返回 32 字节 = `seeds[16] + material[0:16]`。

shellcode 符号 `oracle_code_start` / `oracle_code_end` 已导出（.dynsym 可见），XOR 密钥由 3-share 派生：

- **share0**：对 SHA-256 IV 常量做 MBA-Feistel（IDA 中能看到 MOVZ/MOVK 加载的 0x6A09E667 等）
- **share1**：`expand_key_material` 函数前 128 字节代码的分块 CRC32（需通过 ARX 指令签名定位函数）
- **share2**：soKey 字节的旋转 XOR 变换

逆向这三部分后 XOR 解密 shellcode，从末尾 32 字节提取：

```python
oracle_key = bytes(share0[i] ^ share1[i] ^ share2[i] for i in range(16))
dec = bytes(enc[i] ^ oracle_key[i & 0xF] for i in range(code_size))
seeds_raw = dec[-32:-16]       # 16 bytes → struct.unpack('<4I') 得到 4 个 seed
material_0_16 = dec[-16:]      # 16 bytes，Z3 约束用
```

### Z3 求解

已知 288 bits 约束（> 200 bits 输入 → 唯一解）：

```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(25)]
buf = flag + [BitVecVal(0x5A, 8)] * 7

# 组装为 4×64bit，建模 12 轮 ARX + 3 轮 squeeze
# ... (完整代码见 keygen.py)

solver = Solver()
# 约束 1: material[0:16] == oracle 返回的 material (128 bits)
for i in range(16):
    solver.add(material_sym[i] == material_0_16[i])
# 约束 2: material[80:96] == seeds (128 bits)
for i in range(16):
    solver.add(material_sym[80+i] == seeds_bytes[i])
# 约束 3: material[60:64] == rk15 (32 bits)
#   rk15 = EXPECTED_SOKEY_CHECK ^ soKey[12:16]  (从 .rodata 读 check 值)
for i in range(4):
    solver.add(material_sym[60+i] == rk15_bytes[i])

assert solver.check() == sat  # ~5 min
flagB = bytes([solver.model().eval(flag[i]).as_long() for i in range(25)])
```

## 0x04 方案 A 逆向

修复链：`repair_cfg → repair_sbox → repair_constants → repair_semantics → core_compute`

每一步的输出作为下一步的输入参数，最终 `core_compute` 的 state 与目标比较。

### flag[0:4]：BB 跳转偏移

`repair_cfg` 从 .rodata 读取 `BB0_BRANCH_OFF` / `BB1_OFF`（IDA 追踪 LDR 即可），验证：

```
flag[0:4] & 0x03FFFFFF == (BB1_OFF - BB0_BRANCH_OFF) / 4
```

当前值：BB1 - BB0 = 4 → flag[0:4] = 1。

### flag[4]

硬编码检查 `== 0x01`。

### flag[5:9]

只检查非零，填 `0x00000001`。

### flag[9:13]：ADR 编码

```python
imm21 = BB7_OFF - BB6_OFF  # 从 .rodata 的 volatile const 读取
adr_bits = ((imm21 & 0x3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5)
flag_9_12 = struct.unpack('<I', soKey[0:4])[0] ^ adr_bits
```

### flag[13:17]：XTEA delta

标准值 `0x9E3779B9`。验证方式：用它和 LCG 生成的 round_constants 做 16 轮 XTEA 加密 KPT，结果要等于 KCT（两组都在 .rodata）。

### flag[17:21]：LCG seed

```python
# sbox_first 由 flag[9:13] 和 BB6_OFF 决定（xorshift32 key stream）
lcg = (seed ^ (sbox_first * 0x01010101)) & 0xFFFFFFFF
for _ in range(32):
    lcg = (lcg * 1664525 + 1013904223) & 0xFFFFFFFF
```

seed = `0xDEADC0DE`。发现方式：CTF 常见 magic number 试探，或 C 暴力 < 1s。

### flag[21:25]：step2 + step3

Z3 秒解：

```python
# step3_bits = 16 + (round_constants[0] >> 28)
# 8 组 KIN/KOUT 约束 → 唯一确定 step2_amount(5bit) + step3_param(masked 24bit)
from z3 import *
amt = BitVec('amt', 32)
raw = BitVec('raw', 32)
solver.add(ULT(amt, 32))
solver.add(ULT(raw, 0x1000000))
for i in range(8):
    # s3(KIN[i], param) then s2(result, amt) == KOUT[i]
    ...
solver.check()  # instant
```

## 0x05 合成 Flag

```python
flag50 = bytearray(50)
for i in range(25):
    flag50[i*2]     = flagA[i]
    flag50[i*2 + 1] = flagB[i]
print(flag50.hex())
```

**Flag**: `017a00e3001b009401d2045600f8000c0041ebb7dd290b8e1463b9a579df37109e4bdec8c072ad3dde96070f42e4135837ad`

## 0x06 踩坑

1. **别调试**：蜜罐检测 TracerPid/时间差/HWCAP/BRK，触发后 ARX 轮数降低或参数污染
2. **花指令**：`b.eq 1f; .word 0xDEADBEEF` 导致反汇编错位，手动 NOP 掉
3. **Oracle 定位**：stripped binary 中通过 `ror x8,x8,#8` 指令签名定位 `expand_key_material`
4. **seeds 字节序**：oracle 返回的 raw bytes 要 `struct.unpack('<4I')` 不是大端
5. **soKey 溢出**：Java LCG 是 64-bit 运算，Python 要 mask
6. **AI 陷阱**：函数名伪装为 `chacha20_quarter_round`、`sm4_L_transform` 等，别信函数名
