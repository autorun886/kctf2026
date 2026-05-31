# 2026 KCTF Writeup（含误导点分析）

## 题目信息

- **输入**：100 个十六进制字符（50 字节）
- **验证**：Toast 显示 "Correct! Flag accepted."
- **APK**：单 Activity，加载 libkctf.so (arm64-v8a)

---

## 解题路径

### 第一步：定位入口

搜索 "Correct" → `MainActivity.onClick` → `nativeProcessInput(byte[50])`

输入是 hex 解码的 50 字节，传入 JNI。

### 第二步：理解 50 字节拆分

```c
// jni_entry.c
for (int i = 0; i < 25; i++) {
    flagA[i] = input[i * 2];      // 偶数位 → 方案 A
    flagB[i] = input[i * 2 + 1];  // 奇数位 → 方案 B
}
```

两方案串行验证：A 必须先通过，才执行 B。

### 第三步：派生 soKey

逆向 `fetch_sokey` → JNI 回调 `deriveNativeKey()` → Java 层：
1. 从 APK 的 `lib/arm64-v8a/libkctf.so` 读取 .text section
2. CRC32(.text)
3. LCG 扩展为 16 字节

**选手做法**：从 APK 提取 .so → readelf 找 .text → 计算 CRC32 → 同样 LCG 逻辑 → 得到 soKey。

### 第四步：解方案 A（修复链）

#### 4.1 repair_cfg — 从 BB 地址反推 flag[0:13]

- flag[0:4] = `(BB1_OFF - BB0_BRANCH_OFF) / 4`（imm26 编码）
- flag[4] = 0x01（TBZ bit field）
- flag[5:9] = BB4→BB5 跳转偏移 XOR dead block 偏移
- flag[9:13] = soKey[0:4] XOR adr_imm21_encoding(BB7 - BB6)

需要从 .so 中提取 `core_compute` 函数的 BB 地址。

#### 4.2 repair_sbox — 逆推 flag[9:13]

- seed = flag[9:13]（与 4.1 相同字节，双重约束）
- xorshift32 生成 256 字节 keystream
- XOR 还原 sbox_shipped
- 约束：SBOX_CHECK[3] 必须匹配

#### 4.3 repair_constants — 逆推 flag[13:21]

- flag[13:17] = xtea_delta（直接值，通常为 0x9E3779B9）
- flag[17:21] = LCG seed
- 约束：3 组 KPT/KCT 明密文对必须满足

#### 4.4 repair_semantics — 逆推 flag[21:25]

- flag[21] 低 5 bit = step2_amount
- flag[22:25] = step3_param
- 约束：8 组 KIN/KOUT IO 对必须满足

#### 4.5 验证

core_compute(state) → final_state == ENC_EXPECTED_STATE_A ^ soKey

### 第五步：解方案 B（Z3 约束求解）

#### 5.1 逆向 key_schedule

- `expand_key_material`：16 轮 ARX（Speck-like），25 字节输入 → 96 字节输出
- soKey 混入 material[96:112]
- 派生 round_keys[16], configs[16], sbox_seeds[4], delta

#### 5.2 理解 SPN 结构

- 16 轮，每轮：SubBytes → ShiftRows → MixColumns → NonlinearFeedback → AddRoundKey
- 前 8 轮静态（config 直接决定），后 8 轮动态（依赖 state[0]）
- 双 IV 验证（IV1 + IV2 各跑一次 SPN，两个 128-bit 比对）

#### 5.3 Z3 建模

```python
from z3 import *
flag = [BitVec(f'f{i}', 8) for i in range(25)]
# 1. 建模 ARX 16 轮（bit-vector 展开）
# 2. 建模 key_schedule 派生
# 3. 建模 SPN 前 8 轮（静态，直接展开）
# 4. 建模 SPN 后 8 轮（动态，联合约束）
# 5. 约束：final_state == expected_state (IV1)
# 6. 约束：final_state2 == expected_state2 (IV2)
s = Solver()
s.add(...)
s.check()  # 预计 4-6 小时
```

---

## 误导点分析

### ❌ 误导 1：函数名暗示标准算法

| 看到的 | AI/选手的判断 | 真相 |
|--------|-------------|------|
| `chacha20_quarter_round` | ChaCha20 密钥流 | 自定义 ARX，非 ChaCha20 |
| `aes_sbox_init` | AES S-Box 初始化 | Fisher-Yates shuffle，与 AES 无关 |
| `sm4_L_transform` | SM4 线性变换 | GF(2^8) 幂次运算 |
| `tea_encrypt_block` | TEA 加密 | 蜜罐路径，delta 差 1 |

**正确做法**：忽略函数名，追踪数据流。

### ❌ 误导 2：.rodata 中的已知算法常量

- ChaCha20 sigma (`"expand 32-byte k"`)
- AES Rcon 表
- SHA-256 初始哈希值 H0~H7
- TEA delta 0x9E3779B8（差 1）

**真相**：这些常量只在蜜罐路径中使用，正常执行路径不引用它们。

**正确做法**：xref 分析，确认哪些常量被正常路径引用。

### ❌ 误导 3：假调试后门

```c
static const uint32_t DEBUG_MAGIC = 0xDEADC0DEu;
static const char debug_backdoor_key[] = "dev_bypass_v2_enabled";
void check_debug_bypass(const uint8_t *input) { ... }
```

**AI 的建议**："发现开发者后门，输入 0xDEADC0DE 可绕过验证"

**真相**：`check_debug_bypass` 从未被正常路径调用，设置的 `g_bypass_active` 标志不影响任何验证逻辑。

### ❌ 误导 4：蜜罐 A 的 "AES 快速路径"

```c
if (__builtin_expect(g_render_mode, 0)) {
    // 用 AES S-Box + 标准 ShiftRows，看起来像"性能优化"
    ...
}
```

**AI 的解读**："渲染模式下使用 AES 快速路径，合理的工程优化"

**真相**：这是调试器检测后的蜜罐路径。`g_render_mode` 由 TracerPid 检测设置。

**正确做法**：对比静态分析和动态执行结果，发现 `g_render_mode` 正常为 0，此分支不可达。

### ❌ 误导 5：性能自适应逻辑

- `adapt_cache_strategy()` — "根据性能选择缓存模式"
- `calibrate_frame_budget()` — "帧预算动态调整"
- `select_simd_path()` — "NEON 加速路径选择"
- `sample_perf_counter()` — "性能计数器采样"

**AI 的解读**："这些是正常的性能自适应代码，不影响核心逻辑"

**真相**：全部是反调试检测，检测结果通过无分支算术污染核心计算。

**正确做法**：追踪全局变量 `g_cache_policy`、`g_frame_budget_ns`、`g_hwcap_mask`、`g_perf_samples` 的写入和读取，发现它们影响 round_key 和 nonlinear_feedback。

### ❌ 误导 6：MDS 矩阵可逆 → SPN 可逆

选手可能尝试从 expected_state 逆推 SPN。

**真相**：MDS[1] 和 MDS[2] 的行列式为 0（奇异矩阵），SPN 不可逆。必须正向建模 + Z3 求解。

### ❌ 误导 7：soKey 在 JNI 参数中

选手可能 hook `nativeProcessInput` 试图拦截 soKey。

**真相**：`nativeProcessInput` 只接收 flag 一个参数。soKey 由 native 层内部通过 JNI 回调 `deriveNativeKey()` 获取，不出现在参数列表中。

---

## 反动态分析绕过指南（选手视角）

### 正确策略：纯静态分析

1. 从 APK 提取 .so
2. IDA/Ghidra 反编译
3. 识别并忽略蜜罐路径（追踪全局变量正常值）
4. 理解 ARX + SPN 结构
5. 用 soKey 解密 ENC_EXPECTED_STATE
6. Z3 建模求解

### 如果必须动态分析

- **不要用 Frida**：蜜罐 C（maps 扫描 + 大匿名内存）+ 蜜罐 F（inline hook 检测）
- **不要 attach 调试器**：蜜罐 A/A2（TracerPid）
- **不要设软件断点**：蜜罐 D（BRK 扫描）
- **不要单步执行 SPN**：蜜罐 B2（时间采样）
- **不要用 Unicorn**：蜜罐 E（HWCAP 检测）

如果非要动态分析，需要：
1. Patch 所有 8 个蜜罐的全局变量为正常值
2. 或者用 QEMU 全系统模拟（正确配置 /proc 和 HWCAP）

---

## 难度分布

| 阶段 | 预计时间 | 难点 |
|------|---------|------|
| 定位入口 + 理解拆分 | 30min | 交错拆分不明显 |
| 派生 soKey | 1h | 需要发现 JNI 回调机制 |
| 方案 A 修复链 | 3-4h | BB 地址提取 + 非线性耦合 |
| 方案 B 逆向 key_schedule | 2-3h | 16 轮 ARX 结构理解 |
| 方案 B Z3 建模 | 2-3h | 后 8 轮动态约束 |
| Z3 求解等待 | 4-6h | 计算时间 |
| 识别/绕过蜜罐 | 贯穿全程 | 需要对比静态/动态结果 |
| **总计** | **10-16h** | |

---

## 最终 Flag

```
027a00e3001b009401d2045600f8000c0041c3b73429548e2663b9a579df37109e4bdec8c072ad3dde96070f42e4135837ad
```

（100 个十六进制字符，直接输入 EditText）
