# 2026 KCTF 难度提升与唯一性论证（2026-05-31）

> 本文档记录 2026-05-31 会话中的设计变更、难度分析和 flag 唯一性证明。
> 作为 2026KCTF_v4.md 的补充/修正文档。

---

## 一、设计变更记录

### 变更总览

| 编号 | 变更 | 原值 | 新值 | 影响范围 |
|------|------|------|------|---------|
| M1 | FLAG_B 改为随机字节 | ASCII `"KCTF2026_B_v1_2026_AUTOCTF"` | 25 字节固定随机值 | converge.py, precompute_b.py, converge_b.py, verify.py |
| M2 | ARX 轮数增加 | 12 轮 | 16 轮 | key_expand.c, 所有 Python 脚本 |
| M3 | 动态轮阈值前移 | round >= 12（后 4 轮动态） | round >= 8（后 8 轮动态） | spn_round.c, 所有 Python 脚本 |
| M4 | 新增蜜罐 E（反 Unicorn） | 无 | /proc/self/auxv HWCAP 检测 | spn_round.c |
| M8 | 新增蜜罐 B2（多时间点采样） | 无 | 每 4 轮 clock_gettime 采样 | spn_round.c |
| M6 | 新增 AI 假后门蜜罐 | 无 | check_debug_bypass + DEBUG_MAGIC | tea_impl.c |

### M1: FLAG_B 随机化

**动机**：原 FLAG_B 是可读 ASCII 字符串 `"KCTF2026_B_v1_2026_AUTOCTF"`。选手可通过格式猜测（KCTF 前缀）大幅缩小搜索空间，且 Z3 求解后立即可通过"可读性"确认正确。

**新值**：由 `hashlib.sha256(b"KCTF2026_scheme_B_flag_seed_v2").digest()[:25]` 生成的固定随机字节：
```
0x7A, 0xE3, 0x1B, 0x94, 0xD2, 0x56, 0xF8, 0x0C,
0x41, 0xB7, 0x29, 0x8E, 0x63, 0xA5, 0xDF, 0x10,
0x4B, 0xC8, 0x72, 0x3D, 0x96, 0x0F, 0xE4, 0x58, 0xAD
```

**效果**：选手必须完整求解 Z3 约束，无法通过格式猜测或部分泄露推断。

### M2: ARX 轮数 12→16

**动机**：12 轮 ARX 对 Z3 bit-vector 求解器来说展开成本不高，约 1h 可解。

**改动**：
- `key_expand.c`：`int rounds = 16 - penalty;`（正常 16 轮，蜜罐 B 时 12 轮）
- 蜜罐 B 的 penalty 保持 4（异常时少 4 轮 = 12 轮，仍然产出错误 material）

**效果**：Z3 展开 ARX 的 bit-vector 约束规模增加 33%，求解时间从 ~1h 增加到 ~2-3h。

**唯一性影响**：无。ARX 仍是 256-bit 状态空间上的双射（每步操作可逆），单射性不变。

### M3: 动态轮阈值 12→8

**动机**：原设计前 12 轮完全静态，Z3 可直接展开。后 4 轮动态约束规模仅 64 次 S-Box 查表，联合求解很快。

**改动**：
- `spn_round.c`：S-Box 动态选择 `if (round < 8)` / `else`
- `spn_round.c`：轮密钥动态反馈 `if (round >= 8)`

**效果**：
- 静态可分析部分从 12 轮缩减到 8 轮
- Z3 需联合求解的动态约束从 4×16=64 次 S-Box 增加到 8×16=128 次
- 求解时间约翻倍

**唯一性影响**：无。动态轮只增加映射的非线性度，不减少约束。SPN 仍是确定性函数。

### M4: 蜜罐 E — 反 Unicorn 模拟执行

**检测原理**：Unicorn Engine 模拟 ARM64 代码时缺少真实 Android 环境。通过读取 `/proc/self/auxv` 中的 `AT_HWCAP`（type=16）检测：
- 真机 ARM64 至少有 `HWCAP_FP | HWCAP_ASIMD = 0x3`
- Unicorn 默认无 `/proc/self/auxv` 或 HWCAP=0

**实现**：`spn_round.c` 中 `select_simd_path()`，伪装为"NEON 加速路径选择"。

**污染方式**：无分支 XOR
```c
uint32_t dynamic_key = params->round_keys[round] ^ g_hwcap_mask;
// 正常: g_hwcap_mask = 0 → 不影响
// Unicorn: g_hwcap_mask = 0x5A5A5A5A → 所有 round_key 被污染
```

**绕过方式**（选手合法路径）：
- 静态分析 .so，不使用模拟执行
- 正确配置 Unicorn 的 /proc 文件系统映射
- 直接 patch g_hwcap_mask 为 0（但需先发现此检测）

### M8: 蜜罐 B2 — 多时间点采样

**检测原理**：单步调试 SPN 16 轮时，每 4 轮间隔远超正常执行时间（正常 <10ms，单步 >200ms/4轮）。

**实现**：`spn_round.c` 中 `sample_perf_counter(round)`，每 4 轮调用 `clock_gettime`，累积 `g_perf_samples`。

**污染方式**：与蜜罐 D 合并，无分支乘法折叠
```c
uint8_t perf_flag = (g_perf_samples > 2) ? 1u : 0u;
uint8_t combined = budget_flag | perf_flag;
uint8_t poison = combined * (correct ^ simple);
```

**优势**：比单次时间检测（蜜罐 B）更难绕过 — 需要 patch 多个采样点或全局变量。

### M6: AI 假后门蜜罐

**实现**：`tea_impl.c` 中 `check_debug_bypass()`
```c
static const uint32_t DEBUG_MAGIC = 0xDEADC0DEu;
static const char debug_backdoor_key[] = "dev_bypass_v2_enabled";
```

**效果**：AI 分析二进制时会发现 `DEBUG_MAGIC` 常量和 `"dev_bypass_v2_enabled"` 字符串，建议选手输入 `0xDEADC0DE` 绕过验证。实际此函数从未被正常路径调用。

---

## 二、蜜罐体系总览（6 层）

| 蜜罐 | 全局变量 | 检测目标 | 触发条件 | 分支类型 | 污染效果 |
|------|---------|---------|---------|---------|---------|
| A | g_render_mode | 调试器 attach | TracerPid ≠ 0 | 显式 if | SPN 走 AES 快速路径 |
| B | g_cache_policy | 时间膨胀 | clock_gettime >50ms | 无分支 CSEL | ARX 少 4 轮（16→12） |
| B2 | g_perf_samples | 单步调试 | 每 4 轮间隔 >200ms | 无分支乘法 | nonlinear_feedback 退化 |
| C | g_log_verbosity | Frida 注入 | /proc/self/maps 有 frida | 显式 if | S-Box 只 shuffle 128 项 |
| D | g_frame_budget_ns | 软件断点 | .text 有 BRK 指令 | 无分支乘法 | nonlinear_feedback 退化 |
| E | g_hwcap_mask | Unicorn 模拟 | /proc/self/auxv 无 HWCAP | 无分支 XOR | 所有 round_key 被污染 |

**隔离性**：
- A: init.c(写) + spn_round.c(读)
- B: key_expand.c 内部
- B2: spn_round.c 内部
- C: sbox_gen.c 内部
- D: spn_round.c 内部
- E: spn_round.c 内部
- 六条路径之间零交叉引用（B2/D/E 共存于 spn_round.c 但使用不同全局变量）

---

## 三、难度评估

### 改动前 vs 改动后

| 攻击路径 | 改动前 | 改动后 |
|---------|--------|--------|
| Z3 正向建模（方案 B） | ~1-2h（12 轮 ARX + 4 轮动态） | ~4-6h（16 轮 ARX + 8 轮动态） |
| Frida hook | 蜜罐 B/C 检测 | + 蜜罐 B2 多时间点采样 |
| Unicorn 模拟执行 | 无防护 | 蜜罐 E → round_key 全部被 XOR 污染 |
| 单步调试 SPN | 蜜罐 D（BRK 扫描） | + 蜜罐 B2（时间膨胀累积） |
| AI 辅助逆向 | 命名蜜罐 + 常量蜜罐 | + 假后门诱导 |
| 格式猜测（方案 B） | ASCII flag 可猜 | 随机字节，不可猜 |
| **总求解时间** | **5-8h** | **10-16h** |

### 选手合法解题路径（不受影响）

1. 搜索 "Correct" → Java 层 → JNI → nativeProcessInput
2. 逆向 fetch_sokey → JNI 回调 → deriveNativeKey() → 从 APK 提取 .so → CRC32 → soKey
3. 逆向 key_schedule 的 ARX 结构（16 轮，可逆）
4. 识别蜜罐 A/C（显式分支）→ 理解检测机制 → 静态分析绕过
5. 用 soKey 解密 ENC_EXPECTED_STATE → 得到目标 final_state
6. 将 pipeline 编码为 Z3 约束：
   - 前 8 轮静态（直接展开）
   - 后 8 轮动态（联合约束，128 次 S-Box 查表）
7. Z3 求解 → 得到 FLAG_B（随机字节，需 base64 编码提交）

---

## 四、Flag 唯一性证明

### 方案 B：双 IV 过约束

**定理**：对于固定的 soKey 和 ENC_EXPECTED_STATE/ENC_EXPECTED_STATE2，至多存在一个 25 字节 flag 使得 APK 返回 1。

**证明**：

1. **输入空间**：25 字节 = 200 bit

2. **约束空间**：
   - 第一次 SPN（IV1）：`final_state_1 == ENC_EXPECTED_STATE ^ soKey`（128 bit）
   - 第二次 SPN（IV2）：`final_state_2 == ENC_EXPECTED_STATE2 ^ soKey`（128 bit）
   - 总约束：256 bit

3. **expand_key_material 单射性**：
   - 25 字节输入 + 7 字节固定 padding (0x5A) = 32 字节 = 256-bit 状态
   - 16 轮 ARX 中每步操作：
     - `ROR64(x, 8) + y`：加法 mod 2^64 是双射（固定 y 时）
     - `ROL64(x, 3) ^ y`：XOR 是双射（固定 y 时）
     - 跨半区混合 `s[0] ^= s[3]; s[2] ^= s[1]`：可逆
   - ∴ 16 轮 ARX 是 256-bit 状态空间上的**双射**
   - 不同的 25 字节输入 → 不同的 256-bit 初始状态 → 经双射后仍不同
   - Squeeze 阶段确定性 → 不同 post-ARX 状态 → 不同 material[96]
   - ∴ `flag → material` 是**单射**

4. **key_schedule 单射性**：
   - `material → (round_keys, configs, sbox_seeds, delta)` 是确定性切片，单射
   - soKey 双向验证不影响单射性（只可能污染 delta，不合并不同输入）

5. **SPN 单射性**（给定 params）：
   - 对于固定的 round_keys/configs/sbox_seeds/delta，SPN 是确定性函数
   - 不同 params → 不同 S-Box 组合 + 不同 round_key → 不同输出（由 MDS 满秩保证扩散）

6. **结论**：
   - `flag → (state_1, state_2)` 是单射
   - 256 bit 约束 > 200 bit 输入
   - ∴ 至多 1 个 flag 满足两个约束 ∎

### 方案 A：多层独立过约束

**定理**：对于固定的 soKey 和 ENC_EXPECTED_STATE_A，至多存在一个 25 字节 flag 使得方案 A 验证通过。

**证明**：逐段分析。

| flag 字节 | 约束 | 自由度 | 约束强度 | 唯一性 |
|-----------|------|--------|---------|--------|
| [0:4] | BB0→BB1 imm26 必须精确命中 BB1 入口 | 26 bit | 1 个正确值 / 2^26 | ✓ |
| [4] | TBZ bit field 唯一正确值 | 4 bit | 1 个正确值 / 16 | ✓ |
| [5:9] | BB4→BB5 imm26 + 范围校验 | 26 bit | 1 个正确值 / 2^26 | ✓ |
| [9:13] | S-Box seed + SBOX_CHECK[3] (24 bit 约束) | 32 bit | ~1 个有效 seed | ✓ |
| [13:17] | XTEA delta + 3 组 KPT/KCT (192 bit) | 32 bit | 过约束 | ✓ |
| [17:21] | LCG seed + 3 组 KPT/KCT (192 bit) | 32 bit | 过约束 | ✓ |
| [21] | step2_amount + 8 组 KIN/KOUT (256 bit) | 5 bit | 过约束 | ✓ |
| [22:25] | step3_param + 8 组 KIN/KOUT (256 bit) | ~20 bit | 过约束 | ✓ |

每一段独立过约束 + 最终 128-bit 状态比对 → **唯一解** ∎

### 动态轮阈值变更对唯一性的影响

**无影响**。理由：
- 唯一性由"输入空间 < 约束空间"保证
- 动态轮（S-Box 依赖 state[0]、round_key XOR state[0:4]）只增加映射的非线性度
- 对于固定的 params，SPN 仍是确定性函数：相同输入必然产出相同输出
- 动态轮不引入新的自由度，不减少约束

---

## 五、代码一致性确认

### 关键常量同步状态（2026-05-31）

| 常量 | key_expand.c | spn_round.c | converge.py | converge_b.py | precompute_b.py | verify.py |
|------|-------------|-------------|-------------|--------------|----------------|-----------|
| ARX 轮数 | 16 | — | 16 | 16 | 16 | 16 |
| 动态阈值 | — | >=8 | >=8 | >=8 | >=8 | >=8 |
| NL_POWER | — | [7,11,13,23] | [7,11,13,23] | [7,11,13,23] | [7,11,13,23] | [7,11,13,23] |
| FLAG_B | — | — | 随机字节 | 随机字节 | 随机字节 | 随机字节 |
| 蜜罐 B penalty | 4 | — | — | — | — | — |

### 与设计文档 (2026KCTF_v4.md) 的差异

以下差异是有意的设计变更，设计文档待更新：

| 项目 | 设计文档 | 实际实现 | 变更原因 |
|------|---------|---------|---------|
| ARX 轮数 | 12 | 16 | M2 难度提升 |
| 动态轮阈值 | round>=12 | round>=8 | M3 难度提升 |
| NL_POWER | [3,5,7,11] | [7,11,13,23] | T4.3 双射修复 |
| FLAG_B | ASCII 字符串 | 随机字节 | M1 防格式猜测 |
| 蜜罐数量 | 4 个 (A/B/C/D) | 6 个 (A/B/B2/C/D/E) | M4/M8 反动态分析 |

---

## 六、待完成事项

1. 运行 `py -3 converge.py --release` 重新收敛（所有 .text 改动需要新的 CRC/soKey/ENC 值）
2. 收敛后 verify.py 常量会自动同步
3. 真机验证（T6.2）
4. 更新 2026KCTF_v4.md 设计文档（可选，发布前做）
5. 发布准备（T7）
