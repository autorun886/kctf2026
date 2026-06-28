# 2026 KCTF 逆向题 — 设计亮点与构造思路

## 定位

Android ARM64 逆向，面向顶级选手。预期解题时间 6-10 小时，要求选手具备：
- ARM64 指令编码知识
- Z3/SMT 约束求解建模能力
- 反混淆与反调试对抗经验
- 密码学原语（ARX/SPN/XTEA/Fisher-Yates）的工程直觉

---

## 核心架构：双方案交错验证

输入 50 字节按奇偶拆分为两个独立方案：

| | 方案 A（显式修复链） | 方案 B（隐式密码验证） |
|--|--|--|
| 输入 | 偶数字节 25B | 奇数字节 25B |
| 验证方式 | 参数逐步修复 → 正向计算比对 | ARX 扩展 → SPN 加密比对 |
| 求解手段 | 静态逆向 + 少量暴力 | Z3 约束求解 (~5 min) |
| 设计意图 | 考察逆向深度 | 考察建模能力 |

两方案顺序依赖（A 必须先通过），但求解完全独立。选手无法从一个方案的结果推导另一个。

---

## 亮点 1：自收敛常量系统

### 问题

soKey 派生自 .text 的 CRC32，但 .text 中包含依赖 soKey 的验证常量。
修改常量 → CRC 变化 → soKey 变化 → 常量需要重算 → 死循环。

### 解决方案

`converge.py` 实现迭代收敛：
1. 所有 soKey 依赖的常量放在 `.rodata`（volatile const，编译器用 LDR 加载）
2. `.text` 只包含代码逻辑，不含数据字面量
3. 迭代构建直到 CRC 稳定（通常 2 轮）

这使得 APK 完整性与验证逻辑形成自洽闭环——修改任何代码字节都会导致 soKey 失效。

---

## 亮点 2：跨模块耦合的常量加密（const_xor）

.rodata 中的验证目标（KCT/KOUT/SBOX_CHECK 等）经 XOR 加密存储。
密钥不是固定值，而是**从 3 个不同源文件的固定常量动态派生**：

```
piece0 = CRC32(KPT_array)                  ← repair_constants.c
piece1 = IV_A[0] ^ ror32(IV_A[2], 13)      ← core_compute.c
piece2 = LE_u32(IV[0:4]) ^ LE_u32(IV2[0:4]) ← jni_entry.c
key = LCG_expand(piece0 ^ piece1 ^ piece2)
```

### 设计意图

- 强制选手理解多模块结构（不能只看一个函数）
- LCG 与 round_constants 生成同源 — 逆向一处触类旁通
- 密钥不依赖 .text CRC → 不参与收敛循环 → 工程稳定

---

## 亮点 3：修复链的依赖拓扑（方案 A）

```
repair_cfg ──→ dispatch_table[0]
                    │
                    ▼
repair_sbox ──→ sbox_shipped[256] ──→ sbox_first
                                          │
                                          ▼
repair_constants ──→ round_constants[32] ──→ rc_high4
                         │                      │
                         ▼                      ▼
              repair_semantics ──→ step2_amount / step3_param
                                          │
                                          ▼
                                   core_compute
                                          │
                                          ▼
                               ENC_EXPECTED_STATE_A
```

每一步的输出作为下一步的输入参数。选手必须**完整还原整条链**才能验证任何一步的正确性。
不存在"跳过中间步骤直接对比最终结果"的捷径。

### flag 字段的 soKey 绑定

- `flag[5:9]`：`expected ^ soKey[8:12]`（BB 偏移 + APK 绑定）
- `flag[9:13]`：`ADR_encode(BB7-BB6) ^ soKey[0:4]`（ARM64 编码 + APK 绑定）

选手必须同时掌握 ARM64 指令编码和 soKey 派生才能构造这两个字段。

---

## 亮点 4：Oracle 的三重密钥保护

方案 B 的 Z3 约束来源（seeds + material[0:16]）藏在 XOR 加密的 shellcode 中。
解密密钥由 3 个独立 share 异或组成：

| Share | 来源 | 逆向难度 |
|-------|------|---------|
| 0 | MBA-Feistel（SHA-256 IV 常量） | 识别混合布尔算术 |
| 1 | expand_key_material 代码前 128 字节的 CRC32 | 在 stripped binary 中定位函数 |
| 2 | soKey 字节旋转变换 | 理解 Java→Native 数据流 |

三条路径完全独立，任意一条出错都导致 shellcode 解密失败。

---

## 亮点 5：Z3 可解性的精心调控

### 约束设计

| 已知信息 | 比特数 | Z3 求解时间 |
|----------|--------|------------|
| seeds only (128 bits) | 128 | 超时 ✗ |
| seeds + sokey_check (160 bits) | 160 | 超时 ✗ |
| material[0:32] (256 bits) | 256 | 50s ✓ |
| seeds + material[0:16] (288 bits) | 288 | ~4 min ✓ |

最终选择 288 bits：刚好可解（~5 分钟），但不可暴力。
选手必须正确建模 12 轮 ARX + 3 轮 squeeze 的完整符号表达式。

### 不可绕过性

- Fisher-Yates S-Box 不可符号化 → 选手不能把 SPN 放进 Z3
- 必须先通过 Oracle 获取 seeds → 预计算 S-Box → 才能验证 Z3 解

---

## 亮点 6：蜜罐矩阵（无分支设计）

| 蜜罐 | 检测目标 | 触发后果 | 分支方式 |
|-------|---------|---------|---------|
| A/A2 | TracerPid | S-Box 替换 | 显式 if |
| B | clock_gettime 时间差 | ARX 轮数 12→8 | 算术：`penalty = (ns > 200ms) * 4` |
| B2 | 每 4 轮采样 | NL_feedback 污染 | 算术累加 |
| C | 大匿名可执行段 | round_key 异常 | 显式 if |
| D | BRK 断点扫描 | step2_amount 翻转 | 算术：`flag ^= (count>0)` |
| E | HWCAP 异常 | round_key 污染 | 算术 |
| F | libc inline hook | delta 污染 | 算术：`poison = (score>0) * 0xCAFECAFE` |

关键设计：无分支蜜罐用**算术表达式**替代 if/else，使得：
1. 反编译器无法识别为"检测+惩罚"模式
2. 符号执行引擎无法通过路径约束绕过
3. IDA 中看起来只是普通计算

---

## 亮点 7：反 AI 诱饵

- 函数名伪装：`chacha20_quarter_round`（实为 ARX 扩展）
- 假后门：`DEBUG_MAGIC`、`"dev_bypass_v2_enabled"` 字符串
- 花指令条件来自输入：`g_opaque = input[0]`，IDA 无法确定分支方向
- `.word 0xDEADC0DE` / `0xBAADF00D` 等魔数在 dead code 中诱导 AI 误判

---

## 亮点 8：唯一性保证

50 字节 flag 的每一位都被精确约束：

- **方案 A**：7 个字段均有独立的精确验证（BB 比对 / soKey 绑定 / KCT / KOUT）
- **方案 B**：288 bits 约束 > 200 bits 输入空间 → 信息论保证唯一解
- **交错映射**：偶数位↔方案A，奇数位↔方案B，双射

不存在任何"部分正确"能通过验证的情况。

---

## 工程特色

| 工具 | 用途 |
|------|------|
| `converge.py` | 自动收敛 + 常量加密 + Oracle patch + APK 签名 |
| `keygen.py` | 选手视角的自包含求解器（含 Z3 建模） |
| `verify.py` | Python 侧正向模拟验证 |

整个构建流程一键完成：`python converge.py --debug` → 收敛 → 验证 → 产出可部署 APK。
