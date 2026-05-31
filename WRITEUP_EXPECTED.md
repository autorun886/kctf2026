# 预期题解

> 本文档描述出题方预期的完整解题路径。
> 方案 A（显式修复）难度较低，方案 B（隐式修复）难度较高。

---

# 方案 A：显式修复

> 难度定位：Android 逆向 + 约束反推。不需要 Z3，逐段求解即可。

---

## 第一阶段：初步侦察

### 1.1 APK 解包 & 定位校验点

```bash
apktool d challenge_a.apk -o out/
```

jadx 搜索 `"Correct"` → 定位 `nativeProcessInput`，返回 1 = 正确。
输入格式：Base64 → 25 字节。

### 1.2 发现修复函数

IDA 分析 `nativeProcessInput_A`，发现调用链：

```
repair_cfg(flag, soKey)
repair_sbox(flag, dispatch_table[0] & 0xFF)
repair_constants(flag, sbox[0])
repair_semantics(flag, round_constants[0] >> 28)
```

**关键发现**：4 个修复函数串行调用，每个函数的输出作为下一个的输入参数（非线性耦合）。

---

## 第二阶段：soKey 派生（与方案 B 相同）

参见方案 B 第二阶段。soKey 从 .so 的 .text 段 CRC32 派生，离线计算。

---

## 第三阶段：逐段反推 flag

### 3.1 flag[0:9] — 控制流修复约束

`repair_cfg` 修复 4 处控制流破坏：

**BB0→BB1 跳转（flag[0:4]）**：
```c
*b_insn ^= (*(uint32_t*)&flag[0]) & 0x03FFFFFF;
```
修复后目标必须精确命中 BB1 入口。BB1 入口地址固定（编译时确定），因此 imm26 的正确值唯一，flag[0:4] 唯一确定。

```python
# 从 .so 读取 BB0 末尾的 B 指令（已破坏）
broken_insn = read_u32(so_data, BB0_BRANCH_OFFSET)
# BB1 入口相对 B 指令的偏移 → 正确 imm26
correct_imm26 = (BB1_ADDR - BB0_BRANCH_ADDR) >> 2
# flag[0:4] = broken_insn.imm26 ^ correct_imm26（低 26 bit）
flag_0_3 = (broken_insn ^ correct_imm26) & 0x03FFFFFF
```

**BB2→BB3 条件码（flag[4] 低 4 bit）**：
```c
*csel_insn ^= ((uint32_t)(flag[4] & 0x0F)) << 12;
```
CSEL 的正确 cond 由前置 CMP 指令决定（唯一），因此 flag[4] 低 4 bit 唯一确定。

**dispatch table（flag[5:9]）**：
```c
table[i] ^= *(uint32_t*)&flag[5] ^ *(uint32_t*)&soKey[0];
```
正确偏移 = BB7 入口 - table 基址（唯一），soKey 已知，因此 flag[5:9] 唯一确定。

### 3.2 flag[9:13] — S-Box 修复约束

```c
uint32_t seed = *(uint32_t*)&flag[9];
// xorshift32 展开 256 字节 key_stream
// XOR 还原，起始偏移 = dispatch_table[0] & 0xFF（已从 3.1 得到）
```

正确 S-Box 必须是双射（256 个不同值各出现恰好一次）。
xorshift32 周期 2^32-1，不同 seed 产出不同 key_stream，给定目标置换和 XOR 结构，seed 唯一。

```python
# 枚举或逆推：已知 sbox_shipped（发布时的破坏版本）和 offset
# 逆 Fisher-Yates 或直接搜索满足双射约束的 seed
```

### 3.3 flag[13:21] — 常量修复约束

```c
xtea_delta = *(uint32_t*)&flag[13];
uint32_t lcg = *(uint32_t*)&flag[17] ^ (uint32_t)sbox_first * 0x01010101u;
// LCG 展开 32 个 round_constants
```

内嵌 3 组已知 (plaintext, ciphertext) 对，每组 64 bit：
```
encrypt(pt_i, delta, round_constants) == ct_i  (i = 0, 1, 2)
```

3 组提供 192 bit 约束，自由度仅 64 bit（delta 32 + seed 32）→ 过约束，唯一解。
可用 Z3 或暴力搜索（2^32 × 2^32 空间，但约束强，实际可快速收敛）。

### 3.4 flag[21:25] — 语义修复约束

```c
// step2：循环左移 flag[21] & 0x1F 位
// step3：非线性混合，有效位数 = 16 + (round_constants[0] >> 28)
//        param = flag[22:25]（有效位数由 rc_high4 决定）
```

内嵌 8 组 (input, expected_output) 测试对，提供 256 bit 约束，远超自由度 → 唯一解。

---

## 第四阶段：验证 & 提交

```python
flag_bytes = flag_0_3_bytes + flag_4_byte + flag_5_8_bytes + \
             flag_9_12_bytes + flag_13_16_bytes + flag_17_20_bytes + \
             flag_21_byte + flag_22_24_bytes

import base64
print("提交 Flag:", base64.b64encode(flag_bytes).decode())
```

## 解题路径总结（方案 A）

```
APK 解包 → 定位 nativeProcessInput_A
  └─ 发现 4 个修复函数（repair_cfg / repair_sbox / repair_constants / repair_semantics）
       └─ 离线计算 soKey（CRC32 + LCG）
            └─ 识别蜜罐（A/C 显式，B/D 无分支）
                 └─ 从 BB 地址反推 flag[0:9]（纯结构约束）
                      └─ 双射约束反推 flag[9:13]
                           └─ 明密文对约束反推 flag[13:21]
                                └─ IO 对约束反推 flag[21:25]
                                     └─ Base64 编码提交
```

**核心难点排序**：
1. 理解 4 个修复点的非线性耦合（必须按序求解）
2. 识别并绕过 4 个蜜罐（尤其是无分支的 B/D）
3. 从 BB 地址结构反推 flag[0:9]（需要理解 ARM64 B 指令编码）
4. 正确派生 soKey（JNI 回调机制）

---

---

# 方案 B：隐式修复

> 难度定位：Android 逆向 + 密码学分析 + Z3 约束求解三项能力。

---

## 第一阶段：初步侦察

### 1.1 APK 解包

```bash
apktool d challenge.apk -o out/
unzip challenge.apk -d out/
```

关注：
- `out/lib/arm64-v8a/libchallenge.so` — 核心逻辑
- `out/smali/com/kctf/challenge/MainActivity.smali` — Java 层

### 1.2 定位校验点

在 jadx 中搜索字符串 `"Correct"` 或 `"Wrong"`，直接定位到：

```java
int result = nativeProcessInput(flag);
if (result == 1) {
    Toast.makeText(this, "Correct! Flag accepted.", Toast.LENGTH_LONG).show();
} else {
    Toast.makeText(this, "Wrong, try again.", Toast.LENGTH_SHORT).show();
}
```

**结论**：校验在 native 层，`nativeProcessInput` 返回 1 = 正确。

### 1.3 输入格式

```java
byte[] flag = Base64.decode(editText.getText().toString(), Base64.DEFAULT);
nativeProcessInput(flag);
```

**结论**：用户输入 Base64 字符串，解码后得到 25 字节传入 native。

---

## 第二阶段：soKey 派生

### 2.1 发现 JNI 回调

在 IDA/Ghidra 中分析 `Java_com_kctf_challenge_MainActivity_nativeProcessInput`，
发现函数内部调用了 `GetMethodID` + `CallObjectMethod`，方法名为 `"deriveNativeKey"`，签名 `"()[B"`。

**关键发现**：native 层主动回调 Java 层获取 soKey，不在参数列表中传递。

### 2.2 分析 deriveNativeKey()

回到 jadx 查看 `deriveNativeKey()`：

```
1. 解析 /proc/self/maps → 找 libchallenge.so 的 r-xp 段 → 得到 execStart, execEnd
2. 读取 /proc/self/mem[execStart:execEnd] → .text 字节
3. CRC32(.text) → crcVal (32-bit)
4. 4 轮 LCG 扩展 → soKey[16]
```

LCG 参数：
```java
long[] EXPAND = {0xA3F1B28C7D4E5F60L, 0x9C8B7A6D5E4F3021L,
                 0x1F2E3D4C5B6A7980L, 0xD0E1F2038495A6B7L};
// 每轮：m = (crcVal ^ EXPAND[i]) * 0x5851F42D4C957F2DL + 0x14057B7EF767814FL
// 取 m 的高 32 位（字节 24~27）作为 key[i*4 : i*4+4]
```

### 2.3 离线计算 soKey

```python
import struct, zlib

with open("libchallenge.so", "rb") as f:
    data = f.read()

# 从 ELF 头解析 .text 段范围（PT_LOAD, PF_X）
text = data[text_offset : text_offset + text_size]
crc_val = zlib.crc32(text) & 0xFFFFFFFF

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

print("soKey:", soKey.hex())
```

---

## 第三阶段：识别并绕过蜜罐

### 3.1 蜜罐 A（显式分支，最容易发现）

在 `spn_round` 函数入口处发现：

```c
if (__builtin_expect(g_render_mode, 0)) {
    // 走 AES 快速路径（标准 AES S-Box + shift_rows_standard）
    // 注意：没有 MixColumns，结果错误
    return;
}
```

追踪 `g_render_mode` 的写入点 → `early_init()` (constructor)：TracerPid != 0 时设置。

**结论**：不要 attach 调试器。

### 3.2 蜜罐 C（显式分支，第二容易发现）

在 `generate_sbox` 函数入口：

```c
if (!g_logging_checked) {
    adjust_logging();  // 扫描 /proc/self/maps
    g_logging_checked = 1;
}
int limit = (g_log_verbosity == 0x02) ? 255 : 128;
```

**结论**：不要用 Frida 注入。

### 3.3 蜜罐 B（无分支，需要对比数值）

在 `expand_key_material` 中：

```c
adapt_cache_strategy();
int penalty = (g_cache_policy != 0x03) * 4;
int rounds = 12 - penalty;
```

调试器单步时时间膨胀 → 只跑 8 轮 → 结果错误。
**绕过**：离线模拟时直接用 12 轮。

### 3.4 蜜罐 D（无分支，最隐蔽）

在 `nonlinear_feedback` 首轮：

```c
uint8_t budget_flag = (g_frame_budget_ns < 16000000ULL);
uint8_t poison = budget_flag * (correct ^ simple);
state[i] = correct ^ poison;
```

**识别方法**：注意 `budget_flag * (correct ^ simple)` 乘法折叠模式。
**绕过**：不打软件断点，或离线模拟时直接用 `gf_pow` 路径。

### 3.5 soKey 双向验证（无分支污染）

在 `key_schedule` 末尾：

```c
uint32_t diff = check ^ EXPECTED_SOKEY_CHECK;
uint32_t poison = ((diff | (~diff + 1)) >> 31) * 0xDEADBEEF;
params->delta ^= poison;
```

**绕过**：正确派生 soKey（第二阶段已完成），此处自动通过。

---

## 第四阶段：逆向核心算法

### 4.1 整体架构

```
flag[25] → key_schedule(flag, soKey) → params
                                          ↓
                                    generate_sbox × 4 → sboxes[4][256]
                                          ↓
                                    spn_encrypt(IV, params, sboxes) → final_state
                                          ↓
                              final_state == decrypt(ENC_EXPECTED_STATE, soKey) ?
```

### 4.2 key_schedule 逆向

`expand_key_material`（伪装名 `chacha20_quarter_round`）：

```
输入：flag[25] + padding[7] = s[4]（4 个 uint64）
12 轮 ARX：
  s[0] = ror64(s[0], 8) + s[1] ^ r
  s[1] = rol64(s[1], 3) ^ s[0]
  s[2] = ror64(s[2], 8) + s[3] ^ (r+4)
  s[3] = rol64(s[3], 3) ^ s[2]
  s[0] ^= s[3]; s[2] ^= s[1]
Squeeze 3 次（每次 32 字节）→ material[96]
```

material 布局：
```
[0:64]   → round_keys[16]（每 4 字节一个）
[64:80]  → configs[16]（每字节拆 4 个 2-bit 字段）
[80:96]  → sbox_seeds[4]
[96:112] → material[0:16] ^ soKey → delta 从 [96:100] 取
```

### 4.3 S-Box 生成

`generate_sbox`（伪装名 `aes_sbox_init`）：

```python
def generate_sbox(seed):
    sbox = list(range(256))
    xs = seed
    for i in range(255, 0, -1):
        xs ^= (xs << 13) & 0xFFFFFFFF
        xs ^= (xs >> 17) & 0xFFFFFFFF
        xs ^= (xs << 5)  & 0xFFFFFFFF
        j = xs % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox
```

### 4.4 SPN 加密（16 轮）

每轮操作顺序：SubBytes → ShiftRows → MixColumns → NonlinearFeedback → AddRoundKey

```
前 12 轮：
  dynamic_key = round_keys[round]
  sbox_sel    = configs[round].sbox_selector

后 4 轮（round >= 12）：
  dynamic_key = round_keys[round] ^ state[0:4]   ← 动态反馈
  sbox_sel    = (configs[round].sbox_selector ^ state[0]) & 0x03
```

**ShiftRows**：4 种模式 `{0,1,2,3}` / `{0,1,3,4}` / `{0,2,3,1}` / `{0,3,1,2}`

**MixColumns**：4 个 MDS 矩阵，GF(2^8) 矩阵乘法（不可约多项式 0x11B）

**NonlinearFeedback**（伪装名 `sm4_L_transform`）：
```
power = {3, 5, 7, 11}[mode]
round_const = (delta >> (round%4 * 8)) & 0xFF
state[i] = gf_pow(state[i] ^ round_const ^ round, power)
```

**AddRoundKey**：`state[i] ^= ((uint8_t*)&round_key)[i % 4]`

### 4.5 获取目标状态

`ENC_EXPECTED_STATE[16]` 在 .rodata 中，用 soKey 解密：

```python
expected_state = bytes(ENC_EXPECTED_STATE[i] ^ soKey[i] for i in range(16))
```

---

## 第五阶段：Z3 约束求解

### 5.1 策略

将整个正向 pipeline 编码为 Z3 bit-vector 约束，让 Z3 求解 flag。

**分段策略**（利用前 12 轮静态的特性）：

```
Step 1: 用 Z3 对 key_schedule 建模
        flag[25] → material[128] → params

Step 2: 前 12 轮 SPN 可以用 Z3 符号执行
        state_12 = SPN_rounds_0_to_11(IV, params)

Step 3: 后 4 轮联合约束（动态反馈）
        state_16 = SPN_rounds_12_to_15(state_12, params)
        约束：state_16 == expected_state
```

### 5.2 Z3 模型骨架

```python
from z3 import *

flag = [BitVec(f'flag_{i}', 8) for i in range(25)]

def expand_key_material_z3(flag_syms):
    s = [Concat(*flag_syms[i*8:(i+1)*8]) for i in range(4)]
    for r in range(12):
        s[0] = (RotateRight(s[0], 8) + s[1]) ^ r
        s[1] = RotateLeft(s[1], 3) ^ s[0]
        s[2] = (RotateRight(s[2], 8) + s[3]) ^ (r + 4)
        s[3] = RotateLeft(s[3], 3) ^ s[2]
        s[0] ^= s[3]
        s[2] ^= s[1]
    material = []
    for _ in range(3):
        material.extend(s)
        s[0] += s[2]; s[1] ^= s[3]
        s[2] = RotateLeft(s[2], 17); s[3] = RotateRight(s[3], 11)
    return material[:96]

def sbox_lookup_z3(sbox_concrete, x_sym):
    result = BitVecVal(sbox_concrete[255], 8)
    for i in range(254, -1, -1):
        result = If(x_sym == i, BitVecVal(sbox_concrete[i], 8), result)
    return result

solver = Solver()
for i in range(25):
    solver.add(flag[i] >= 0x20, flag[i] <= 0x7E)

# 建立 key_schedule 约束，混入 soKey（已知常量）
# 建立 SPN 约束（前 12 轮符号执行，后 4 轮联合）
# 目标约束
for i in range(16):
    solver.add(final_state[i] == expected_state[i])

if solver.check() == sat:
    m = solver.model()
    flag_bytes = bytes(m[flag[i]].as_long() for i in range(25))
    import base64
    print("Flag (Base64):", base64.b64encode(flag_bytes).decode())
```

### 5.3 求解时间预估

| 组件 | Z3 约束规模 | 备注 |
|------|------------|------|
| ARX 12 轮 | 中等（加法进位链） | 可分段 |
| 前 12 轮 SPN | 中等（192 次 S-Box ITE） | 静态，可预计算 |
| 后 4 轮 SPN | 较重（64 次 S-Box ITE + 动态反馈） | 联合约束 |
| GF 幂运算 | 中等（每次 2-4 次 gf_mul） | 可展开 |

预计求解时间：**1-4 小时**。

---

## 第六阶段：验证

```python
flag_bytes = b'...'  # Z3 求解结果
soKey = compute_sokey("libchallenge.so")

params = key_schedule(flag_bytes, soKey)
sboxes = [generate_sbox(params.sbox_seeds[i]) for i in range(4)]
state = list(IV)
spn_encrypt(state, params, sboxes)

expected = [ENC_EXPECTED_STATE[i] ^ soKey[i] for i in range(16)]
assert bytes(state) == bytes(expected), "验证失败"

import base64
print("提交 Flag:", base64.b64encode(flag_bytes).decode())
```

---

## 解题路径总结（方案 B）

```
APK 解包
  └─ jadx 搜索 "Correct" → 定位 nativeProcessInput
       └─ IDA 分析 .so → 发现 JNI 回调 deriveNativeKey
            └─ 离线计算 soKey（CRC32 + LCG）
                 └─ 识别 4 个蜜罐（A/C 显式，B/D 无分支）
                      └─ 逆向 key_schedule（ARX）+ SPN（16 轮）
                           └─ 用 soKey 解密 ENC_EXPECTED_STATE
                                └─ Z3 约束求解 flag[25]
                                     └─ Base64 编码提交
```

**核心难点排序**：
1. 识别并绕过 4 个蜜罐（尤其是无分支的 B/D）
2. 正确逆向 key_schedule 的 ARX 结构（伪装为 ChaCha20）
3. 正确建立 Z3 模型（任何一个操作建模错误 = UNSAT）
4. 理解 JNI 回调机制，正确派生 soKey

**不需要**：暴力破解、逆向 SPN（从输出反推输入）、破解 SHA-256。
