# 2026 KCTF 理想解题流程

> 本文档描述出题方预期的解题路径。两方案均需解出，最终提交 50 字节交错 flag。

---

## 第一步：定位入口（共用）

1. 反编译 APK，搜索字符串 `"Correct! Flag accepted."` → 定位 `MainActivity.onClick`
2. 发现 JNI 调用 `nativeProcessInput(byte[] flag)`，参数为 50 字节
3. 加载 `libkctf.so`，找到 `Java_com_autorun_kctf_MainActivity_nativeProcessInput`
4. 分析入口逻辑：
   - 50 字节交错拆分：`flagA[i] = input[i*2]`，`flagB[i] = input[i*2+1]`
   - 调用 `fetch_sokey` → JNI 回调 Java 层 `deriveNativeKey()`
   - 顺序验证：`verify_scheme_a(flagA, soKey)` 通过后才运行 `verify_scheme_b(flagB, soKey)`

---

## 第二步：派生 soKey（共用）

逆向 `fetch_sokey` 发现它通过 JNI `CallObjectMethod` 回调 Java 层 `deriveNativeKey()`。

`deriveNativeKey()` 逻辑：
1. 解析 `/proc/self/maps`，找 `libkctf.so` 的 `r-xp` 映射段地址
2. 通过 `/proc/self/mem` 读取 `.text` 段字节
3. 计算 `CRC32(.text)`
4. 用 4 轮 LCG 扩展为 16 字节 soKey：
   ```
   m = (crc ^ EXPAND[i]) * 0x5851F42D4C957F2D + 0x14057B7EF767814F
   key[i*4..i*4+3] = m[31:0] 的高4字节
   ```

**选手做法**：从 APK 提取 `.so`，用相同算法离线计算 soKey（约 10 分钟）。

---

## 第三步：方案 A 求解（低难度）

### 3.1 识别修复链结构

`verify_scheme_a` 顺序调用四个修复函数，每步输出作为下一步输入：

```
repair_cfg(flagA, soKey)
    ↓ dispatch_table[0] & 0xFF
repair_sbox(flagA, cfg_dep)
    ↓ sbox_shipped[0]
repair_constants(flagA, sbox_first)
    ↓ round_constants[0] >> 28
repair_semantics(flagA, rc_high4)
    ↓
core_compute(state)  →  比对 ENC_EXPECTED_STATE_A ^ soKey
```

### 3.2 求解 flagA[0:9]（控制流约束）

`repair_cfg` 修复 4 处控制流破坏，修复后必须命中 `VALID_BB_OFFSETS` 中的合法地址：

- **flagA[0:4]**：BB0 的 `B` 指令 imm26 被 XOR，修复后必须跳到 BB1 入口
  - 从 `VALID_BB_OFFSETS` 和 `BB0_BRANCH_OFF` 直接读出目标偏移，反推 XOR key
- **flagA[4]** 低 4 bit：BB2 的 `TBZ` bit 字段被 XOR，修复后必须测试 bit#0
  - 读出破坏后的指令，计算还原 bit#0 所需的 XOR 值
- **flagA[5:9]**：BB4 `B` 指令 + BB6 `ADR` 指令 imm 被 `flagA[5:9] ^ soKey[0:4]` XOR
  - 已知 soKey，已知目标地址（BB5 和 BB7 入口），直接反推

**结果**：flagA[0:9] 唯一确定，无需枚举。

### 3.3 求解 flagA[9:13]（S-Box seed）

`repair_sbox` 用 xorshift32(seed) 生成 256 字节 key_stream，XOR 还原 `sbox_shipped`。

约束：修复后的 `sbox_shipped` 必须是双射（256 个不同值）。

**选手做法**：
- 从二进制读出 `sbox_shipped`（破坏后的非双射版本）
- 枚举 2^32 个 seed，检查 XOR 结果是否双射（约 18 分钟单线程，可并行）
- 加上 `SBOX_CHECK[3]` 验证（T4.2 实现后）：3 字节已知对将有效 seed 压到唯一

### 3.4 求解 flagA[13:21]（XTEA 参数）

`repair_constants` 从 flagA[13:17] 读 `xtea_delta`，从 flagA[17:21] 读 LCG seed（混入 `sbox_shipped[0]`），展开 32 个 `round_constants`。

约束：3 组 KPT/KCT 明密文对必须匹配：
```
xtea_check_encrypt(KPT[i]) == KCT[i]  for i in 0..2
```

**选手做法**：
- 从二进制读出 `KPT[3][2]` 和 `KCT[3][2]`
- 已知 `sbox_shipped[0]`（上一步求出），代入 LCG 混入公式
- 用 Z3 或手算对 64-bit 空间（delta + seed）建立 3 组约束，唯一解

### 3.5 求解 flagA[21:25]（语义参数）

`repair_semantics` 从 flagA[21] 读 `step2_amount`，从 flagA[22:25] 读 `step3_param`（有效位数由 `round_constants[0] >> 28` 决定）。

约束：8 组 KIN/KOUT IO 对必须匹配：
```
step2(step3(KIN[i], step3_param), step2_amount) == KOUT[i]  for i in 0..7
```

**选手做法**：从二进制读出 KIN/KOUT，对 40-bit 空间建立 8 组约束，唯一解。

---

## 第四步：方案 B 求解（高难度）

### 4.1 逆向 key_schedule

`expand_key_material`（伪装名 `chacha20_quarter_round`）：
- 25 字节 flag 填充到 32 字节，跑 12 轮 ARX
- Squeeze 输出 96 字节 material
- soKey XOR 混入 material[96:112]
- 从 material 派生 round_keys[16]、configs[16]、sbox_seeds[4]、delta

**选手需要理解**：
- ARX 结构（非 ChaCha20，但形式相似）
- material 布局：round_keys 来自 [0:64]，configs 来自 [64:80]，seeds 来自 [80:96]，delta 来自 [96:100]（已混入 soKey）
- soKey 双向验证（无分支）：错误 soKey 会污染 delta

### 4.2 识别并绕过蜜罐

四个独立蜜罐，分散在不同编译单元：

| 蜜罐 | 检测方式 | 触发效果 | 识别方法 |
|------|---------|---------|---------|
| A (g_render_mode) | TracerPid 检测 | SPN 走 AES 快速路径 | 显式 if 分支，IDA 可见 |
| B (g_cache_policy) | 时间差检测 | ARX 只跑 8 轮 | 无分支 CSEL，需对比正常/异常值 |
| C (g_log_verbosity) | maps 扫描 | Fisher-Yates 只 shuffle 128 项 | 显式 if 分支，IDA 可见 |
| D (g_frame_budget_ns) | BRK 扫描 | nonlinear_feedback 退化为 XOR | 无分支乘法折叠 |

**选手做法**：不使用调试器，纯静态分析 + 离线模拟，四个蜜罐自然不触发。

### 4.3 理解 SPN 结构

16 轮 SPN，每轮：SubBytes → ShiftRows → MixColumns → NonlinearFeedback → AddRoundKey

关键特性：
- 4 个动态 S-Box（xorshift32 + Fisher-Yates，seed 来自 flag）
- 4 个 MDS 矩阵（GF(2^8)）
- 4 种 ShiftRows 模式
- 4 种非线性幂次（gf_pow，幂次与 255 互质，双射）
- **后 4 轮动态耦合**：`actual_key = round_keys[N] ^ state[0:4]`，`sbox_sel = config ^ state[0] & 3`

**关键洞察**：SPN 不可逆（MDS[1]/MDS[2] 奇异），逆推路径不可行，必须正向建模。

### 4.4 Z3 约束求解

将完整 pipeline 编码为 Z3 bit-vector 约束：

```python
# 伪代码
flag = [BitVec('f%d' % i, 8) for i in range(25)]

# 1. ARX key schedule
material = model_expand_key_material(flag)  # 12轮ARX + squeeze
material[96:112] = [material[i] ^ soKey[i] for i in range(16)]
round_keys, configs, sbox_seeds, delta = extract_params(material)

# 2. S-Box 生成（xorshift32 + Fisher-Yates）
sboxes = [model_generate_sbox(sbox_seeds[i]) for i in range(4)]

# 3. SPN 16轮
state = list(IV)
for rnd in range(16):
    dyn_key = round_keys[rnd]
    if rnd >= 12:
        dyn_key ^= state[0:4]  # 动态反馈
    state = spn_round(state, configs[rnd], dyn_key, delta, rnd, sboxes)

# 4. 约束
expected = [ENC_EXPECTED_STATE[i] ^ soKey[i] for i in range(16)]
solver.add([state[i] == expected[i] for i in range(16)])
# T4.1 实现后：加第二个 IV2 的约束
expected2 = [ENC_EXPECTED_STATE2[i] ^ soKey[i] for i in range(16)]
solver.add([state2[i] == expected2[i] for i in range(16)])

result = solver.check()  # 预计 1-3 小时
```

**编码技巧**：
- gf_pow 用 256-entry 查表（`Array` 或嵌套 `If`），避免展开 GF 乘法
- Fisher-Yates 的 `bvurem` 除数是具体值，Z3 可优化
- 后 4 轮动态 sbox_sel：枚举 4^4=256 种组合，或让 Z3 处理符号化 If

---

## 第五步：合并提交

```python
flagA = bytes(25)  # 方案A求解结果
flagB = bytes(25)  # 方案B求解结果

# 50字节交错合并
flag50 = bytearray(50)
for i in range(25):
    flag50[i*2]   = flagA[i]
    flag50[i*2+1] = flagB[i]

import base64
print(base64.b64encode(flag50).decode())
```

---

## 难度定位

| 方案 | 预期时间 | 核心难点 |
|------|---------|---------|
| 方案 A | 2-4 小时 | 修复链逆向 + KPT/KCT 约束求解 |
| 方案 B | 4-8 小时 | ARX key schedule 逆向 + Z3 建模 |
| 合计 | 6-12 小时 | 两方案串行，方案 A 是方案 B 的前置 |

---

## 非预期路径说明

| 路径 | 可行性 | 原因 |
|------|-------|------|
| 方案 B 逆推 SPN | 不可行 | MDS[1]/MDS[2] 奇异，MixColumns 不可逆 |
| 方案 B 暴力枚举 flag | 不可行 | 2^200 搜索空间 |
| 方案 B 差分/线性分析 | 不可行 | 单已知明文（一个 IV） |
| 方案 A 跳过 S-Box 枚举 | 可行 | 最终 ENC_EXPECTED_STATE_A 会过滤，但需要 T4.2 实现 SBOX_CHECK |
| 蜜罐绕过（patch 全局变量） | 可行但不影响 | 纯静态分析自然绕过，patch 需要找到 4 个独立变量 |
