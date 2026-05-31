# 难度提升计划：强化结构修复特征 + 反动态分析 + AI 蜜罐增强

## 目标

将总求解时间从 5-8h 提升到 10-16h，难度来源于：
1. 理解修复结构的拓扑关系（而非堆计算量）
2. 反动态调试/模拟执行让 Frida/Unicorn 路径失效
3. AI 蜜罐让 LLM 辅助逆向产出错误分析

## 改动清单

---

### M1. FLAG_B 改为随机字节（阻止格式猜测）

**文件**：`converge.py`（build_flag 中 FLAG_B 定义）

**改动**：将 `b"KCTF2026_B_v1_2026_AUTOCTF!!"[:25]` 改为固定的 25 字节随机值（用 seed 生成，可复现）。

**效果**：选手无法通过 flag 格式猜测缩小搜索空间，必须完整求解。

**收敛影响**：需要重新收敛（ENC_EXPECTED_STATE 变化）。

---

### M2. ARX 轮数 12→16（增加 Z3 约束规模）

**文件**：`key_expand.c` 第 59 行，`converge.py`，`precompute_b.py`，`verify.py`

**改动**：
- `int rounds = 12 - penalty;` → `int rounds = 16 - penalty;`
- 蜜罐 B 的 penalty 保持 4（异常时 12 轮而非 16 轮）
- 所有 Python 脚本中 ARX 循环同步改为 16

**效果**：Z3 展开 ARX 的 bit-vector 约束规模增加 33%，求解时间从 ~1h 增加到 ~2-3h。

**收敛影响**：改变 .text，需要重新收敛。

---

### M3. 动态轮扩展：后 8 轮（round >= 8）

**文件**：`spn_round.c`，`key_expand.c`（spn_encrypt 中的 `if (round >= 12)`）

**改动**：
- `if (round >= 12)` → `if (round >= 8)`（轮密钥动态反馈）
- S-Box 动态选择同步改为 `round >= 8`

**效果**：
- 静态可分析部分从 12 轮缩减到 8 轮
- Z3 需要联合求解的动态约束从 4 轮×16 S-Box = 64 次增加到 8 轮×16 = 128 次
- 求解时间约翻倍

**收敛影响**：改变 .text，需要重新收敛。

---

### M4. 反 Unicorn/模拟执行：环境指纹检测（新增蜜罐 E）

**原理**：Unicorn Engine 模拟执行时缺少真实 Android 环境。检测方式：
1. 读取 `/proc/self/auxv` 中的 AT_HWCAP（ARM64 硬件能力位）
2. 真机有 NEON/AES/SHA 等位，Unicorn 默认全零或缺失
3. 无分支折叠：用 HWCAP 的特定 bit 作为 XOR mask 混入 round_key

**新文件**：不新建文件，嵌入 `spn_round.c` 的 `spn_encrypt` 中。

**实现**：
```c
// 在 spn_encrypt 入口，首次调用时读取 AT_HWCAP
static volatile uint32_t g_hwcap_mask = 0;
static int g_hwcap_checked = 0;

static void check_hwcap(void) {
    // 读 /proc/self/auxv，找 AT_HWCAP (type=16)
    int fd = open("/proc/self/auxv", O_RDONLY);
    if (fd < 0) { g_hwcap_mask = 0; return; }
    uint64_t buf[2];
    while (read(fd, buf, 16) == 16) {
        if (buf[0] == 16) {  // AT_HWCAP
            // 真机 ARM64 至少有 HWCAP_FP|HWCAP_ASIMD = 0x3
            // 如果 bit0 和 bit1 都为 1 → 正常 → mask=0
            // 否则（Unicorn 默认）→ mask=0x5A5A5A5A → 污染 round_key
            g_hwcap_mask = ((buf[1] & 0x3) == 0x3) ? 0 : 0x5A5A5A5Au;
            break;
        }
        if (buf[0] == 0) break;  // AT_NULL
    }
    close(fd);
}
```

**无分支折叠**：
```c
// 在 spn_encrypt 循环中
uint32_t dynamic_key = params->round_keys[round] ^ g_hwcap_mask;
```

**效果**：
- Unicorn 模拟执行 → HWCAP 缺失 → round_key 全部被 XOR 0x5A5A5A5A → 结果错误
- 真机/正确模拟器 → mask=0 → 不影响
- 无分支，IDA/AI 看不到条件跳转
- 选手必须正确设置 Unicorn 的 HWCAP 或直接从 .so 静态分析

**收敛影响**：改变 .text，需要重新收敛。

---

### M5. 反 Frida：GOT/PLT 完整性校验（新增蜜罐 F）

**原理**：Frida inline hook 修改 GOT 表条目。在 SPN 执行前校验关键 GOT 条目的一致性。

**实现位置**：`key_expand.c` 的 `key_schedule` 末尾（与 soKey 双向验证并列）。

**实现**：
```c
// 读取 dlsym 自身的 GOT 条目，与预期值比较
// Frida 替换 GOT 后，条目指向 frida-agent 的 trampoline
// 检测方式：读取 .got 中 clock_gettime 的条目，检查是否在 libc 范围内
static uint32_t got_integrity_check(void) {
    // 通过 dladdr 获取 clock_gettime 的真实地址
    // 与 GOT 中存储的地址比较
    // 不匹配 → 返回非零 poison
    void *got_addr = get_func_by_id(0);  // clock_gettime from GOT
    Dl_info info;
    if (dladdr(got_addr, &info) && info.dli_fname) {
        // 检查是否来自 libc（正常）还是 frida-agent（异常）
        // 简化：检查地址是否在 libkctf.so 范围内（不应该在）
        extern char __executable_start, __etext;
        uintptr_t addr = (uintptr_t)got_addr;
        uintptr_t lo = (uintptr_t)&__executable_start;
        uintptr_t hi = (uintptr_t)&__etext;
        if (addr >= lo && addr < hi) {
            return 0xBADBADBAu;  // GOT 被 hook 到自身范围内（异常）
        }
    }
    return 0;
}
```

**无分支折叠**：
```c
params->delta ^= got_integrity_check();
// 正常 → 返回 0 → delta 不变
// Frida hook → 返回 0xBADBADBA → delta 被污染
```

**评估**：这个检测比较脆弱（Frida 可以 hook dladdr 本身）。作为额外一层防护可以加，但不应作为主要防线。**建议降低优先级或简化为仅检查 GOT 条目地址范围。**

---

### M6. AI 蜜罐增强：假的"调试后门"

**原理**：在 .rodata 中放置一个看起来像"开发者后门"的结构，AI 会建议选手利用它。

**实现**：在 `tea_impl.c` 中添加：
```c
// 看起来像调试后门：如果输入特定 magic → 直接返回成功
// AI 会说："发现后门，输入 0xDEADC0DE 即可绕过验证"
// 实际：这段代码在蜜罐路径中，正常执行永远不会到达
static const uint32_t DEBUG_MAGIC = 0xDEADC0DEu;
static const char debug_msg[] = "debug_bypass_enabled";

void __attribute__((used)) check_debug_bypass(uint32_t input) {
    if (input == DEBUG_MAGIC) {
        // "绕过验证" — 实际只是设置一个无用的标志
        volatile int bypass = 1;
        (void)bypass;
        (void)debug_msg;
    }
}
```

**效果**：AI 分析时会发现这个"后门"并建议选手使用，浪费时间。

---

### M7. AI 蜜罐增强：伪造的 key_schedule 注释

**原理**：在 key_expand.c 的 .rodata 中嵌入误导性的"算法描述"字符串。

**实现**：在 `key_expand.c` 中添加加密存储的误导字符串：
```c
// 这些字符串解密后看起来像算法注释，AI 会据此分析
// 实际它们描述的是蜜罐路径的行为，不是真实路径
static const char mislead_1[] = "ChaCha20-Poly1305 AEAD";
static const char mislead_2[] = "key_len=256, rounds=20";
static const char mislead_3[] = "nonce: first 12 bytes of input";
```

**评估**：效果有限，因为现代 AI 会结合代码结构分析。**建议改为在函数内部添加误导性的 dead code 路径**，比如一个永远不执行但看起来像"简化版 key_schedule"的分支。

---

### M8. 反动态调试增强：多时间点采样（强化蜜罐 B）

**原理**：当前蜜罐 B 只在 expand_key_material 入口做一次时间检测。改为在 SPN 执行过程中做多次采样，累积判断。

**实现位置**：`spn_round.c` 的 `nonlinear_feedback` 中。

**改动**：
```c
// 每 4 轮做一次时间采样，累积到 g_timing_score
static volatile uint32_t g_timing_score = 0;

// 在 nonlinear_feedback 中（每轮调用）
if ((round & 3) == 0 && round > 0) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    // 与上次采样比较，如果间隔异常大（单步调试）→ 累加
    static uint64_t last_ns = 0;
    uint64_t now = t.tv_sec * 1000000000ULL + t.tv_nsec;
    if (last_ns && (now - last_ns) > 100000000ULL) {  // >100ms per 4 rounds
        g_timing_score++;
    }
    last_ns = now;
}

// 在最后一轮（round==15）用 timing_score 污染结果
// 无分支：poison = (g_timing_score > 0) * 0xFF → XOR 到 state
uint8_t time_poison = (g_timing_score > 2) ? 0xFF : 0x00;
// 编译为 CSEL，无跳转
```

**效果**：
- 单步调试 → 每 4 轮间隔 >100ms → timing_score 累积 → 最终结果被污染
- 正常执行 → 16 轮 SPN 总耗时 <10ms → timing_score=0
- 比单次时间检测更难绕过（需要 patch 多个采样点）

**收敛影响**：改变 .text，需要重新收敛。

---

## 优先级排序

| 编号 | 改动 | 难度提升效果 | 实现成本 | 收敛影响 |
|------|------|------------|---------|---------|
| M1 | FLAG_B 随机字节 | ★★★ | 极低 | 需收敛 |
| M2 | ARX 16 轮 | ★★ | 低 | 需收敛 |
| M3 | 动态轮 8→16 | ★★★ | 低 | 需收敛 |
| M4 | 反 Unicorn (HWCAP) | ★★★ | 中 | 需收敛 |
| M8 | 多时间点采样 | ★★ | 中 | 需收敛 |
| M6 | 假后门蜜罐 | ★ | 低 | 不需收敛(.rodata) |
| M7 | 误导字符串 | ★ | 低 | 不需收敛(.rodata) |
| M5 | GOT 完整性 | ★ | 中 | 需收敛 |

## 建议执行顺序

```
M1 + M2 + M3（一起改，只需一次收敛）
    ↓
M4（反 Unicorn，改 .text）
    ↓
M8（多时间点采样，改 .text）
    ↓
收敛（一次性）
    ↓
M6 + M7（AI 蜜罐，只改 .rodata，不需收敛）
    ↓
验证
```

## 预期效果

| 攻击路径 | 改动前 | 改动后 |
|---------|--------|--------|
| Z3 正向建模 | ~1-2h | ~4-6h（ARX 16轮 + 动态 8 轮） |
| Frida hook | 蜜罐 B/C 检测 | + GOT 校验 + 多时间点采样 |
| Unicorn 模拟 | 无防护 | HWCAP 指纹 → 结果错误 |
| AI 辅助逆向 | 命名蜜罐 | + 假后门 + 误导注释 |
| 格式猜测 | ASCII flag 可猜 | 随机字节，不可猜 |
| 总求解时间 | 5-8h | 10-16h |

## 不做的事

- 不加 VM/控制流平坦化（工作量太大，且改变题目性质）
- 不增加 SPN 轮数（16 轮已足够，增加只是堆计算量）
- 不加 ptrace 自附加（兼容性风险高，已有 ipc_verify 占位）
- M5 (GOT 校验) 可选 — Frida 可以 hook dladdr 绕过，效果有限
