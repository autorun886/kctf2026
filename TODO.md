# 2026 KCTF 剩余任务清单

> 基于 2026-05-27 分析结果重写。已完成项不再列出。
> 优先级：🔴 阻塞题目可解性/公平性 → 🟡 影响难度/完整度 → 🟢 锦上添花
> 理想解题流程见 WRITEUP_IDEAL.md

---

## 当前状态快照

| 模块 | 状态 | 说明 |
|------|------|------|
| 方案 B 完整 pipeline | ✅ 完成 | SPN 16轮 + key_schedule + soKey 双向验证 |
| 方案 A 修复链 | ✅ 完成 | repair_cfg/sbox/constants/semantics + core_compute |
| 蜜罐 A/B/C/D（方案 B） | ✅ 完成 | 四个检测点均已实现 |
| Release APK + 常量收敛 | ✅ 完成 | CRC=e9bd9f2e，已签名 |
| KPT/KCT/KIN/KOUT | ✅ 完成 | 方案 A 约束系统已就位 |
| 方案 A 蜜罐 B/D | ✅ 完成 | repair_constants/semantics 均已实现 |
| 花指令（repair_sbox/constants/semantics） | ✅ 完成 | 三文件入口均已加花指令 |
| 方案 B flag 唯一性 | ❌ 缺失 | 200-bit 输入 vs 128-bit 约束，~2^72 有效 flag |
| 方案 A flag[9:13] 唯一性 | ❌ 缺失 | S-Box seed 双射约束不足，~1.6亿有效 seed |
| NL_POWER 非双射 bug | ❌ 缺失 | power=3/5 不是 GF(2^8) 双射，Z3 多解分支，求解变慢 |
| ipc_verify.c | ⚪ 可选 | 返回全零，无 fork/ptrace |
| strings.c 多密钥 | ⚪ 可选 | 单一 XOR 方案，非原设计 6 种来源 |

---

## 🔴 T1：补全方案 A 约束对（阻塞可解性）

**问题**：KPT/KCT 和 KIN/KOUT 全零，flag[13:25] 无约束，选手无法唯一求解。

### T1.1 生成 3 组明密文对（repair_constants.c）

用正确 flag + 正确 soKey 运行修复链，选取 3 组 `(v0v1_in, v0v1_out)` 作为 XTEA 轮函数的已知对：

- 选 3 组不同的 `(v0, v1)` 输入，用正确的 `xtea_delta` + `round_constants` 跑完 16 轮，记录输出
- 填入 repair_constants.c 的 `KPT[3][2]` 和 `KCT[3][2]`
- 在 `repair_constants()` 末尾加验证逻辑：用当前 delta/rc 加密 KPT，比对 KCT，不匹配则走蜜罐

```c
/* 验证逻辑（伪代码）*/
for (int i = 0; i < 3; i++) {
    uint32_t v[2] = {KPT[i][0], KPT[i][1]};
    xtea_encrypt_check(v, xtea_delta, round_constants);
    if (v[0] != KCT[i][0] || v[1] != KCT[i][1])
        goto honeypot_delta;  /* 篡改 delta 差 1 */
}
```

### T1.2 生成 8 组 IO 对（repair_semantics.c）

用正确的 `step2_amount` + `step3_param` + `step3_bits` 计算 8 组 `(input, output)`：

- 选 8 个不同的 `uint32_t` 输入，跑 `step2(step3(x))` 得到输出
- 填入 repair_semantics.c 的 `KIN[8]` 和 `KOUT[8]`
- 在 `repair_semantics()` 末尾加验证逻辑：不匹配则走蜜罐（篡改 step2_amount = 0）

### T1.3 重新收敛常量

KPT/KCT/KIN/KOUT 是 `.rodata` 数据，不影响 `.text` CRC，无需重新收敛 soKey。
但需要重新运行 `precompute_a.py` 确认 ENC_EXPECTED_STATE_A 仍然正确（修复链末尾加了验证逻辑后 final_state 不变，只是增加了蜜罐跳转路径）。

---

## 🔴 T2：方案 A 蜜罐 B/D 补全

**问题**：repair_constants.c 和 repair_semantics.c 无调试检测，方案 A 反调试保护远弱于方案 B。

### T2.1 repair_constants.c 加蜜罐 B（时间差检测）

在 `repair_constants()` 入口调用 `adapt_cache_strategy()`（与 key_expand.c 相同逻辑），读取 `g_cache_policy`，无分支折叠轮数：

```c
void repair_constants(const uint8_t *flag, uint8_t sbox_first) {
    /* 蜜罐 B：时间差检测，无分支 */
    extern volatile uint32_t g_cache_policy;
    int penalty = (g_cache_policy != 0x03u) * 8;  /* 异常时多加 8 轮 LCG */
    ...
    int rc_rounds = 32 + penalty;  /* 正常=32，异常=40（轮常量错误） */
    for (int i = 0; i < rc_rounds; i++) { ... }
    /* 只取前 32 个，但 seed 已被多余轮次污染 */
}
```

注意：`g_cache_policy` 定义在 key_expand.c，需要 `extern` 引用，或在 repair_constants.c 内独立实现一次时间差检测写入局部变量（更隔离，符合原设计"互不引用"原则）。

### T2.2 repair_semantics.c 加蜜罐 D（BRK 扫描）

在 `repair_semantics()` 入口调用 `calibrate_frame_budget()`（与 spn_round.c 相同逻辑），无分支折叠 step2_amount：

```c
void repair_semantics(const uint8_t *flag, uint8_t rc_high4) {
    /* 蜜罐 D：BRK 扫描，无分支 */
    extern volatile uint64_t g_frame_budget_ns;
    uint8_t budget_flag = (g_frame_budget_ns < 16000000ULL) ? 1u : 0u;

    step2_amount = flag[21] & 0x1Fu;
    /* 无分支污染：有断点时 step2_amount 被翻转低 bit */
    step2_amount ^= budget_flag;
    ...
}
```

同样建议在 repair_semantics.c 内独立实现 BRK 扫描，不共享 spn_round.c 的全局变量。

---

## 🟡 T3：repair_sbox / repair_constants / repair_semantics 入口花指令

每个函数入口加一处，各用不同垃圾字节：

```c
/* repair_sbox.c 入口 */
__asm__ volatile("cmp xzr, xzr\n\t" "b.ne 1f\n\t" ".word 0xBAADF00D\n\t" "1:\n\t" ::: "cc");

/* repair_constants.c 入口 */
__asm__ volatile("cmp xzr, xzr\n\t" "b.ne 1f\n\t" ".word 0xDEADC0DE\n\t" "1:\n\t" ::: "cc");

/* repair_semantics.c 入口 */
__asm__ volatile("cmp xzr, xzr\n\t" "b.ne 1f\n\t" ".word 0x0BADC0DE\n\t" "1:\n\t" ::: "cc");
```

加完后需重新收敛（花指令改变 .text，CRC 变化）。

---

## 🔴 T4：修复 flag 唯一性（阻塞题目公平性）

**问题根因**：
- 方案 B：200-bit 输入 vs 128-bit 输出约束，理论上 ~2^72 个不同 25 字节输入都能让 APK 返回 1。Z3 找到的解不一定是预期 flag，选手无法提交。
- 方案 A：flag[9:13]（S-Box seed）的约束仅为"结果是双射"，约 37% 的随机 seed 满足，有效 seed ~1.6 亿个。选手需要枚举所有双射 seed 再逐一验证，而非唯一求解。

**不降低难度的原则**：新增约束必须与现有结构同质（已知对、状态比对），不能直接暴露 flag 字节。

---

### T4.1 方案 B：加第二次 SPN 运行（双 IV 双比对）

**原理**：用相同 params、不同 IV2 再跑一次 SPN，加第二个 128-bit 比对。
- 总约束：256 bit > 200 bit（输入空间）
- 期望有效 flag 数：2^(200-256) = 2^-56 → 唯一
- 对选手影响：Z3 需对两次 SPN 建模，约束规模翻倍，但 key_schedule（ARX）结构不变，难度实质不变

**改动文件**：
1. `jni_entry.c`：加 `IV2[16]`（与 IV1 不同）和 `ENC_EXPECTED_STATE2[16]`；`verify_scheme_b` 中加第二次 `spn_encrypt` + 第二个 `diff2` 比对
2. `precompute_b.py`：加第二次正向模拟，输出 `ENC_EXPECTED_STATE2`
3. `converge.py`：更新正则替换，同步处理 `ENC_EXPECTED_STATE2`

**注意**：IV2 改变 `.rodata` 不影响 `.text` CRC，无需重新收敛 soKey。但 ENC_EXPECTED_STATE2 依赖 soKey，需在收敛完成后由 `precompute_b.py` 计算。

---

### T4.2 方案 A：repair_sbox 加已知对验证

**原理**：在 `repair_sbox` 末尾加 3 字节已知对检查，与 KPT/KCT 性质相同。
- 3 字节 = 24-bit 约束，把有效 seed 从 ~1.6 亿压到 ~1 个
- 对选手：新增一个已知对约束点，和 KPT/KCT 求解方式完全相同，不降低难度

**改动文件**：
1. `repair_sbox.c`：末尾加验证逻辑，不匹配走蜜罐（sbox_shipped 恢复为恒等映射）
2. `precompute_a.py`：计算正确 seed 对应的 `sbox_shipped[0/1/2]` 修复后值，填入 `SBOX_CHECK[3]`

```c
/* 在 repair_sbox() 末尾，XOR 还原后 */
static const uint8_t SBOX_CHECK[3] = {0xXX, 0xYY, 0xZZ};  /* precompute_a.py 填入 */
if (sbox_shipped[0] != SBOX_CHECK[0] ||
    sbox_shipped[1] != SBOX_CHECK[1] ||
    sbox_shipped[2] != SBOX_CHECK[2]) {
    /* 蜜罐：恢复恒等映射，core_compute 结果错误 */
    for (int i = 0; i < 256; i++) sbox_shipped[i] = (uint8_t)i;
    return;
}
```

**注意**：SBOX_CHECK 是 `.rodata`，不影响 `.text` CRC，无需重新收敛。

---

### T4.3 方案 B：修复 NL_POWER 非双射 bug（优化 Z3 速度）

**问题**：`NL_POWER = {3, 5, 7, 11}` 中 power=3（gcd(3,255)=3）和 power=5（gcd(5,255)=5）在 GF(2^8) 上不是双射。Z3 遇到这类约束时必须探索多个解，增加求解时间但不增加技术含量。

**修复**：将 `NL_POWER` 改为全双射幂次：

```c
/* spn_round.c */
static const uint8_t NL_POWER[4] = {7, 11, 13, 23};
/* 验证：gcd(7,255)=1, gcd(11,255)=1, gcd(13,255)=1, gcd(23,255)=1 */
/* 逆幂次：inv(7)=73, inv(11)=116, inv(13)=157, inv(23)=122 (mod 255) */
```

**效果**：
- Z3 每个 gf_pow 约束有唯一解，求解路径确定，预计 Z3 时间从 4-8h 降至 1-3h
- SPN 仍然不可逆（MDS[1]/MDS[2] 奇异），逆推路径仍封死
- 不降低难度：选手仍需正向建模，只是 Z3 跑得更快

**改动文件**：`spn_round.c` 第 62 行，4 字节常量数组

**注意**：NL_POWER 在 `.text` 段（常量数组），改动后必须重新收敛 soKey 和所有 ENC_EXPECTED_STATE。

---

## 🟡 T5：strings.c 升级为多密钥方案（可选）

原设计要求 6 种 key_source，当前为单一 XOR。如果要实现：

- 增加 `str_entry` 结构体（offset, length, key_source, key_param）
- 实现 `derive_str_key()`：6 种来源（SBOX/RCON/DELTA/HMAC/CRC/COMPOUND）
- 蜜罐字符串（"AES-256-CBC"、"ChaCha20" 等）用蜜罐常量解密
- 真实字符串（"/proc/self/status" 等）用运行时状态解密

**评估**：对题目核心难度影响很小，工作量中等。如果时间紧张可跳过。

---

## 🟡 T5：ipc_verify.c 实现（可选）

原设计：fork 子进程 ptrace 父进程 .text，HMAC-SHA256 校验，fallback 机制。

当前：`memset(out, 0, 16)`，等价于 IPC 层不存在。

**评估**：ipc_verify 是"可选加固层"，原文档明确标注。当前全零等价于 fallback 路径，key_schedule 仍然正确运行。实现后增加一层防 patch 保护，但兼容性风险高（部分 ROM 禁止 ptrace）。如果时间紧张可跳过。

---

## 🟢 T6：验证与测试

### T6.1 静态结构验证（可用 Python 脚本完成）

- [ ] 4 个 S-Box 互不相同（逐字节比较）
- [ ] 4 个 S-Box 无仿射等价（DDT 分布不同）
- [ ] 16 个 round_key 互不相同（对正确 flag 运行 key_schedule）
- [ ] 蜜罐路径正常值时不可达（CFG 分析）

### T6.2 功能验证（需真机或模拟器）

- [ ] 正确 50-byte flag → "Correct! Flag accepted."
- [ ] 错误 flag → "Wrong, try again."
- [ ] 蜜罐 A 触发（attach debugger）→ 静默错误
- [ ] 蜜罐 B 触发（时间膨胀）→ 静默错误
- [ ] 蜜罐 C 触发（frida 注入）→ 静默错误
- [ ] 蜜罐 D 触发（BRK 断点）→ 静默错误

### T6.3 选手解题路径验证

- [ ] 方案 A：从 BB 地址反推 flag[0:9] 可行（手动验证一遍）
- [ ] 方案 A：明密文对约束 flag[13:21] 唯一解（T1 完成后验证）
- [ ] 方案 B：Z3 约束求解可在合理时间内完成（预计 <4h）

---

## 🟢 T7：发布准备

- [ ] 题目描述撰写
  - 方案 A（低难度）：提示"程序被破坏，输入 flag 修复它"
  - 方案 B（高难度）：无提示，纯逆向
- [ ] 最终 flag 确认（当前 50-byte 交错 flag 已收敛，确认无误）
- [ ] 提交平台验证

---

## 执行顺序建议

```
T1/T2/T3 ← 已完成
    ↓
T4.3（NL_POWER 修复）← 改 .text，需重新收敛，先做
    ↓
T4.1（方案B双IV）← 改 .rodata，收敛后填入
    ↓
T4.2（方案A SBOX_CHECK）← 改 .rodata，收敛后填入
    ↓
T7.1（解题路径验证）← 按 WRITEUP_IDEAL.md 手动走一遍
    ↓
T6.2（真机验证）← 需要设备
    ↓
T5 / T6（可选，时间允许再做）
    ↓
T7（发布）
```

**注意**：
- T4.3 改变 `.text`，完成后必须重新运行 `converge.py` 收敛 CRC/soKey/ENC_EXPECTED_STATE
- T4.1 和 T4.2 均为 `.rodata`，在收敛完成后由 `precompute_b.py` / `precompute_a.py` 计算填入
- T4.3 + T4.1 + T4.2 全部完成后，再做一次完整 Release 构建验证
