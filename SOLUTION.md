# 2026 KCTF 解题报告

## 一、题目概览

Android ARM64 逆向挑战。APK 中包含 `libkctf.so`，输入为 50 字节 hex（100 字符），
奇偶字节交错后分别送入两个独立验证方案：

- **偶数位字节（25B）→ 方案 A**：显式修复链（控制流修复 + 参数化计算）
- **奇数位字节（25B）→ 方案 B**：隐式修复（ARX 密钥扩展 + SPN 加密验证）

两方案均需 PASS，最终 flag 为 50 字节交错结果的 hex 表示。

**最终 Flag**：`017a00e3001b009401d2045600f8000c0041ebb7dd290b8e1463b9a579df37109e4bdec8c072ad3dde96070f42e4135837ad`

**状态**：✅ 已在真机验证通过（Pixel 6 Pro, Android 15）

---

## 二、信息收集

### 2.1 Java 层分析

**入口定位**：APK 中搜索 "Correct" → `MainActivity.onClick` → `hexDecode(input)` →
`nativeProcessInput(byte[50])`。输入 100 个 hex 字符解码为 50 字节传入 JNI。

**输入拆分**：`nativeProcessInput` 中用 for 循环交错拆分：
- `flagA[25]` = 偶数位字节 (input[0], input[2], ..., input[48])
- `flagB[25]` = 奇数位字节 (input[1], input[3], ..., input[49])

**soKey 派生**：`deriveNativeKey()` 通过 `getApplicationInfo().sourceDir` 获取 APK 路径，
用 `ZipFile` 读取 `lib/arm64-v8a/libkctf.so`，解析 ELF section headers 找到 `.text`，
计算 CRC32，通过 LCG 扩展为 16 字节：

```python
EXPAND = [0xA3F1B28C7D4E5F60, 0x9C8B7A6D5E4F3021,
          0x1F2E3D4C5B6A7980, 0xD0E1F2038495A6B7]
MUL = 0x5851F42D4C957F2D
ADD = 0x14057B7EF767814F
for i in range(4):
    m = ((crc ^ EXPAND[i]) * MUL + ADD) & MASK64
    key[i*4:i*4+4] = bytes([(m>>24)&0xFF, (m>>16)&0xFF, (m>>8)&0xFF, m&0xFF])
```

### 2.2 .rodata 关键常量

当前版本 .rodata 中的验证常量经过 `const_xor` 层加密存储（变量名带 `_ENC` 后缀）。
由于 `get_const_xor_key()` 当前返回全零，加密等于不加密，IDA 中可直接读取。

| 符号 | 大小 | 用途 |
|------|------|------|
| `ENC_EXPECTED_STATE_ENC` | 16B | 方案 B 第一次 SPN 目标（XOR soKey 后比较） |
| `ENC_EXPECTED_STATE2_ENC` | 16B | 方案 B 第二次 SPN 目标（唯一性） |
| `ENC_EXPECTED_STATE_A_ENC` | 16B | 方案 A 验证目标 |
| `IV[16]` / `IV2[16]` | 16B | SPN 初始向量 |
| `EXPECTED_SOKEY_CHECK_ENC` | 4B | soKey 完整性校验 |
| `SBOX_CHECK_ENC[3]` | 3B | S-Box 修复验证 |
| `KCT_ENC[3][2]` | 24B | 方案 A XTEA 约束密文对 |
| `KOUT_ENC[8]` | 32B | 方案 A step2/step3 约束输出 |
| `KPT[3][2]` | 24B | 方案 A XTEA 约束明文对（未加密） |
| `KIN[8]` | 32B | 方案 A step2/step3 约束输入（未加密） |
| `BB0_BRANCH_OFF` 等 | 4×4B | 方案 A 基本块偏移（volatile const） |

### 2.3 Oracle 逆向（seeds + material 暴露）

`get_oracle_material()` 通过 `mmap(RWX)` 执行 ARM64 shellcode：
- SVC 系统调用实现反调试（检测 ptrace/TracerPid、Frida、HWCAP）
- 输出 32 字节明文：`seeds[16] || material[0:16]`

**Oracle 数据布局**（shellcode 区间 `[oracle_code_start, oracle_code_end)`）：
```
shellcode 代码 ... | seeds[16B] | material[0:16] [16B] | <- oracle_code_end
                                                          .word 0 (sentinel, 在 end 之后)
```

**Oracle 加密方案**：shellcode 在 `.rodata` 中 XOR 加密存储，
密钥由 3 个 share 异或得到（16 字节）：

**Share 0** — MBA-Feistel 变换：
- 输入：SHA-256 IV 常量 `{0x6A09E667, 0xBB67AE85, ...}`
- 前 8 字节：`Feistel(c0^c2, c1^c3, keys=c4..c7)`
- 后 8 字节：`Feistel(c4^c6, c5^c7, keys=c0..c3)`
- MBA 原语：`add(a,b) = (a^b) + ((a&b)<<1)`，`xor(a,b) = (a|b) - (a&b)`

**Share 1** — 代码 CRC：
- `expand_key_material` 函数前 128 字节代码
- 分 4×32 字节块，各计算半字节 CRC32
- 需要在 stripped binary 中定位该函数（通过 ARX ror#8 + eor ror#61 签名扫描）

**Share 2** — soKey 变换：
- 前 8 字节：`key[i] = sk[i] ^ rol8(sk[(i+3)&15], 3) ^ rol8(sk[(i+7)&15], 5)`
- 后 8 字节：`key[i] = sk[8+i] ^ rol8(sk[(i+5)&15], 2) ^ rol8(sk[(i+11)&15], 6)`

逆向 3-share 后解密 shellcode 即可获得 `seeds`（128 bits）和 `material[0:16]`（128 bits）。

---

## 三、方案 B 求解（Z3 建模）

### 3.1 ARX 密钥扩展

`expand_key_material(flag_25B)` → 96 字节 material：

**初始化**：`flag[25] + 0x5A*7` 填充为 32 字节 → 4×uint64 LE `s[0..3]`

**ARX 混合**（12 轮 Speck 变体，蜜罐 B 异常时降为 8 轮）：
```
for r in range(12):
    s[0] = (ror64(s[0], 8) + s[1]) ^ r
    s[1] = rol64(s[1], 3) ^ s[0]
    s[2] = (ror64(s[2], 8) + s[3]) ^ (r + 4)
    s[3] = rol64(s[3], 3) ^ s[2]
    s[0] ^= s[3]; s[2] ^= s[1]       # cross-mix
```

**Squeeze**（3 轮，每轮输出 32 字节）：
```
output 32B from s[0..3] LE
s[0] += s[2]; s[1] ^= s[3]
s[2] = rol64(s[2], 17); s[3] = ror64(s[3], 11)
```

### 3.2 Material → SPN 参数

```
material[0:64]   → round_keys[16] (uint32 LE, 每 4 字节一个)
material[64:80]  → configs[16] (每字节拆为 ss/sp/mm/nm 各 2 bit)
material[80:96]  → sbox_seeds[4] (uint32 LE) → Fisher-Yates 生成 S-Box
material[96:112] → material[0:16] ^ soKey[0:16]  (soKey 混入)
delta            → *(uint32*)(material+96)  (即 material[0:4] ^ soKey[0:4])
```

**soKey 校验**：`round_keys[15] ^ soKey[12:16]` == `EXPECTED_SOKEY_CHECK_ENC`，
不匹配则 `delta ^= 0xDEADBEEF`（毒化，SPN 输出错误）。

### 3.3 Z3 约束建模

从 oracle 获得的已知信息：
- `material[0:16]`：128 bits（直接 ARX 输出，squeeze 深度 0）
- `material[80:96]` = seeds：128 bits（squeeze 深度 2）
- `material[60:64]` = round_keys[15]：32 bits（从 EXPECTED_SOKEY_CHECK 反推：`rk15 = check ^ soKey[12:16]`）

**总约束 288 bits > 200 bits flag 空间**，数学保证唯一解。

```python
from z3 import *

# 25 个 8-bit 符号变量
flag_vars = [BitVec(f'f{i}', 8) for i in range(25)]
buf = flag_vars + [BitVecVal(0x5A, 8)] * 7
s = [bytes_to_bv64(buf[i*8:(i+1)*8]) for i in range(4)]

# 12 轮 ARX (符号执行)
for r in range(12):
    s[0] = (ror64(s[0], 8) + s[1]) ^ r
    s[1] = rol64(s[1], 3) ^ s[0]
    s[2] = (ror64(s[2], 8) + s[3]) ^ (r+4)
    s[3] = rol64(s[3], 3) ^ s[2]
    s[0] ^= s[3]; s[2] ^= s[1]

# 3 轮 squeeze 得到 material[0:96] 符号表达式
# 添加约束
solver.add(material[0:16] == known_bytes)
solver.add(material[80:96] == seeds_bytes)
solver.add(material[60:64] == rk15_bytes)

solver.check()  # ~5 分钟
```

### 3.4 SPN 验证

Z3 解出 flag_B 后，正向模拟验证：
1. seeds 已知 → Fisher-Yates (xorshift32) 生成 4 张 S-Box（确定性）
2. 16 轮 SPN（SubBytes → ShiftRows → MixColumns → NonlinearFeedback → AddRoundKey）
3. Round 8：`state_crc = CRC32(state)`，后 8 轮 `dynamic_key ^= state[0:4] ^ state_crc`
4. 验证两次：`SPN(IV1) == ENC_EXPECTED_STATE ^ soKey` 且 `SPN(IV2) == ENC_EXPECTED_STATE2 ^ soKey`

---

## 四、方案 A 求解（修复链逆向）

方案 A 的 flag 各字段可直接从 .so 常量和 soKey 计算或暴力搜索得到。

### 4.1 repair_cfg — flag[0:13]

`repair_cfg` 为纯验证模式（不修改 .text），从 .rodata 读取 BB 偏移进行比较：

| 字段 | 含义 | 求解方式 |
|------|------|---------|
| flag[0:4] | BB0→BB1 跳转偏移 | `(BB1_OFF - BB0_BRANCH_OFF) / 4`，直接从 .rodata 读 BB 偏移计算 |
| flag[4] | TBZ bit 字段 | 固定 `0x01`（repair_cfg 硬编码检查 `(flag[4] & 0x0F) == 0x01`） |
| flag[5:9] | BB4→BB5 偏移 | 任意非零值即可（repair_cfg 仅检查 `!= 0`） |
| flag[9:13] | dispatch table key | `soKey[0:4] ^ ADR_encode(BB7-BB6)`，ADR encoding: immlo=imm21[1:0]<<29, immhi=imm21[20:2]<<5 |

### 4.2 repair_constants — flag[13:21]

- flag[13:17] = XTEA delta：`0x9E3779B9`（标准值，通过尝试 KPT→KCT 验证确认）
- flag[17:21] = LCG seed：`0xDEADC0DE`（通过暴力搜索或 magic number 猜测，验证 KPT→KCT）
- LCG 展开：`lcg = (seed ^ (sbox_first * 0x01010101)); repeat 32: lcg = lcg * 1664525 + 1013904223`
- 验证：对每组 KPT 做 16 轮简化 XTEA 加密，结果必须等于 KCT

### 4.3 repair_semantics — flag[21:25]

- flag[21] = step2_amount：循环左移位数（5 bit），Z3 或暴力（32 种）
- flag[22:25] = step3_param raw：24 bit 值，经 `& ((1<<step3_bits)-1)` mask 后使用
- `step3_bits = 16 + (round_constants[0] >> 28)`
- 验证：`s2(s3(KIN[i], step3_param), step2_amount) == KOUT[i]` 对所有 8 组成立
- Z3 秒级求解（8 组约束足够唯一确定 5+24 = 29 bits）

### 4.4 core_compute 正向模拟

修复链执行完毕后，`core_compute` 执行 XTEA 变体 Feistel 网络，
最终 state XOR soKey 与 `ENC_EXPECTED_STATE_A_ENC` 比对。

---

## 五、Flag 合成

```python
flag_50 = bytearray(50)
for i in range(25):
    flag_50[i*2]     = flag_a[i]   # 偶数位 → 方案 A
    flag_50[i*2 + 1] = flag_b[i]   # 奇数位 → 方案 B
print(flag_50.hex())  # 提交此 100 字符
```

---

## 六、反检测注意事项

| 检测手段 | 触发条件 | 后果 |
|----------|----------|------|
| 蜜罐 A/A2 | TracerPid != 0 | 切换到 AES S-Box（错误 SPN 路径） |
| 蜜罐 B | clock_gettime 时间差 > 200ms | ARX 轮数从 12 降为 8 |
| 蜜罐 B2 | 每 4 轮采样间隔 > 200ms | NL_feedback 结果被污染 |
| 蜜罐 C | /proc/self/maps 大匿名可执行段 | 错误 round_key |
| 蜜罐 D | BRK 断点扫描发现硬件断点 | frame_budget 翻转，NL 退化 |
| 蜜罐 E | HWCAP 异常（getauxval 返回 0） | 污染 round_key（反 Unicorn） |
| 蜜罐 F | libc 函数头被 inline hook | 切换函数指针 |
| 花指令 | 静态分析 | b.eq + .word 垃圾字节，反汇编错位 |
| AI 假后门 | 无 | DEBUG_MAGIC + "dev_bypass_v2_enabled" 诱导 AI 走错 |

**唯一可靠路径**：纯静态 IDA 分析 + Z3 约束求解。动态调试会触发蜜罐。

---

## 七、预计耗时

| 阶段 | 耗时 |
|------|------|
| Java 层 + soKey 逆向 | 30 min |
| .so 静态分析（IDA Pro） | 2-3 h |
| Oracle 3-share 逆向解密 | 1-2 h |
| 方案 A 修复链逆向 + 求解 | 1-2 h |
| 方案 B Z3 建模 + 求解 | 1-2 h（Z3 求解本身 ~5 min） |
| 验证+调试 | 30 min |
| **合计** | **6-10 h** |
