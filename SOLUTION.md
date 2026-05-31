# 2026 KCTF 题解（标准版）

## 题目信息

- **输入**：100 个十六进制字符（50 字节）
- **平台**：Android ARM64
- **Flag**：`027a00e3001b009401d2045600f8000c004146b72629fb8eb963b9a579df37109e4bdec8c072ad3dde96070f42e4135837ad`

---

## Step 1: 定位入口

APK 中搜索 "Correct" → `MainActivity.onClick` → `hexDecode(input)` → `nativeProcessInput(byte[50])`

输入是 100 个 hex 字符，解码为 50 字节传入 JNI。

## Step 2: 理解输入拆分

IDA 中 `nativeProcessInput` 使用 NEON `LD2` 指令做交错拆分：
- `flagA[25]` = 偶数位字节 (input[0], input[2], ..., input[48])
- `flagB[25]` = 奇数位字节 (input[1], input[3], ..., input[49])

方案 A 必须先通过，才执行方案 B。

## Step 3: 派生 soKey

逆向 `fetch_sokey` → JNI 回调 Java `deriveNativeKey()`：
1. 从 APK 的 `lib/arm64-v8a/libkctf.so` 提取 .text section
2. CRC32(.text)
3. LCG 扩展为 16 字节：`m = (crc ^ EXPAND[i]) * MUL + ADD`

```python
import struct, zlib, zipfile
z = zipfile.ZipFile('app-release.apk')
so = z.read('lib/arm64-v8a/libkctf.so')
# 解析 ELF 找 .text，计算 CRC32，LCG 扩展
```

## Step 4: 解方案 A

### 4.1 repair_cfg — flag[0:13]

从 .so 中定位 `core_compute` 函数的 BB 地址：
- flag[0:4] = `(BB1_OFF - BB0_BRANCH_OFF) / 4`
- flag[4] = 0x01
- flag[5:9] = BB4→BB5 跳转偏移 XOR dead block 偏移
- flag[9:13] = soKey[0:4] XOR adr_encoding(BB7 - BB6)

### 4.2 repair_sbox — flag[9:13]

xorshift32(seed) 生成 256 字节 keystream，XOR 还原 sbox_shipped。
约束：SBOX_CHECK[3] 必须匹配。

### 4.3 repair_constants — flag[13:21]

- flag[13:17] = XTEA delta（通常 0x9E3779B9）
- flag[17:21] = LCG seed（混入 sbox[0]）
- 约束：3 组 KPT/KCT 明密文对

### 4.4 repair_semantics — flag[21:25]

- flag[21] = step2_amount (5 bit)
- flag[22:25] = step3_param
- 约束：8 组 KIN/KOUT IO 对

## Step 5: 解方案 B

### 5.1 逆向 key_schedule

`expand_key_material`：16 轮 ARX (Speck-like)，25 字节 → 96 字节。
注意：不是 ChaCha20（虽然函数名暗示）。

### 5.2 Z3 建模

```python
from z3 import *
flag = [BitVec(f'f{i}', 8) for i in range(25)]
# 建模 16 轮 ARX
# 建模 key_schedule 派生
# 建模 SPN 前 8 轮（静态）
# 建模 SPN 后 8 轮（动态：round_key ^= state[0:4] ^ CRC32(state_at_r8)）
# 约束：state == ENC_EXPECTED_STATE ^ soKey (IV1)
# 约束：state2 == ENC_EXPECTED_STATE2 ^ soKey (IV2)
```

关键：后 8 轮有中间状态 CRC32 混入 round_key，需要在 Z3 中展开 CRC32 为 bit-vector 约束。

## Step 6: 合并提交

```python
flag50 = bytearray(50)
for i in range(25):
    flag50[i*2] = flagA[i]
    flag50[i*2+1] = flagB[i]
print(flag50.hex())  # 100 hex chars
```

---

## 注意事项

- **不要用 Frida**：maps 扫描 + 大匿名内存检测 + inline hook 检测
- **不要 attach 调试器**：TracerPid 检测（加载时 + 执行时）
- **不要设断点**：BRK 指令扫描
- **不要用 Unicorn**：HWCAP 检测 + 中间状态 CRC 混入
- **纯静态分析 + Z3 是唯一可靠路径**
