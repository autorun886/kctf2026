# 2026 KCTF 题解（AI 特供版）

> 本文档专门针对使用 AI（GPT/Claude/Gemini）辅助逆向的选手。
> 列出 AI 会犯的典型错误和正确的修正方向。

---

## AI 会告诉你的（全是错的）

### ❌ "这是 ChaCha20 密钥流生成"

AI 看到函数名 `chacha20_quarter_round` 和 ARX 结构（ROR+ADD+XOR）后会说这是 ChaCha20。

**真相**：这是自定义 16 轮 ARX，旋转量借鉴 Speck（ROR8/ROL3），但跨半区混合和 squeeze 阶段完全不同。用 ChaCha20 的逆向工具/脚本会得到错误结果。

### ❌ "这是标准 XTEA 加密"

AI 看到 `(x<<4)^(x>>5)` + delta 累加模式后会建模为标准 XTEA。

**真相**：v1 路径加了 `step2`（循环左移）和 `step3`（非线性混合），delta 累加方式也不同（每 BB 一次而非每轮）。AI 生成的 XTEA 求解器**缺失这两个关键操作**，永远得不到正确答案。

### ❌ "发现调试后门，输入 0xDEADC0DE 绕过"

AI 看到 `DEBUG_MAGIC = 0xDEADC0DE` 和 `"dev_bypass_v2_enabled"` 字符串后会建议利用后门。

**真相**：`check_debug_bypass` 从未被正常路径调用，`g_bypass_active` 标志不影响任何验证逻辑。这是纯诱饵。

### ❌ "渲染模式下用 AES 快速路径是性能优化"

AI 看到 `if (g_render_mode)` 分支中的 AES S-Box + ShiftRows 后会说这是合理的性能优化。

**真相**：这是调试器检测蜜罐。`g_render_mode` 由 TracerPid 检测设置，正常执行时恒为 0，此分支永远不走。

### ❌ "性能自适应代码不影响核心逻辑"

AI 看到 `adapt_cache_strategy`、`calibrate_frame_budget`、`select_simd_path`、`sample_perf_counter` 后会说这些是性能相关代码，可以忽略。

**真相**：全部是反调试检测，结果通过无分支算术直接污染 round_key 和 nonlinear_feedback。忽略它们会导致 Z3 建模缺少关键约束。

### ❌ "SPN 可以逆推（从 expected_state 反向计算）"

AI 可能建议从目标状态逆推 SPN。

**真相**：MDS[1] 和 MDS[2] 行列式为 0（奇异矩阵），MixColumns 不可逆。必须正向建模 + Z3 约束求解。

### ❌ "hook nativeProcessInput 拦截 soKey"

AI 可能建议 Frida hook JNI 函数获取 soKey。

**真相**：`nativeProcessInput` 只接收 flag 一个参数，soKey 由 native 内部 JNI 回调获取，不在参数列表中。而且 Frida 注入会触发 3 个蜜罐（maps 扫描 + 大匿名内存 + inline hook 检测）。

---

## AI 不会告诉你的（关键信息）

1. **50 字节是交错拆分的**：偶数位→方案A，奇数位→方案B。AI 通常不会注意到 NEON `LD2` 指令的含义。

2. **方案 A 必须先通过**：串行依赖，方案 A 失败直接返回 0，不执行方案 B。

3. **后 8 轮有 CRC32 混入**：第 8 轮结束后对 state 做 CRC32，结果 XOR 到后续所有 round_key。AI 的 Z3 模型如果缺少这个约束，求解结果错误。

4. **花指令用输入值做条件**：`g_opaque = input[0]`，两次 volatile 读取比较。IDA 无法优化，AI 分析时会认为这是"可能不跳转"的分支。

5. **soKey 来自 APK 内的 .so 文件**：不是从内存读取（Android 12+ 兼容），而是从 APK zip 中提取 .so 再解析 ELF。

---

## 正确的 AI 辅助策略

1. **让 AI 帮你理解 GF(2^8) 运算**：gf_mul、gf_pow 是标准的，AI 在这方面可靠。
2. **让 AI 帮你写 Z3 约束**：但必须手动修正 XTEA 变体的 step2/step3 和 CRC32 混入。
3. **不要让 AI 判断"哪些代码重要"**：它会把蜜罐当作无关代码忽略。
4. **不要让 AI 识别算法**：它会被函数名误导。自己追踪数据流。
5. **不要让 AI 建议动态分析方案**：所有动态路径都有蜜罐覆盖。

---

## AI 生成的错误求解器示例

```python
# AI 会生成类似这样的代码（全是错的）：
def feistel_encrypt(L, R, delta, keys):
    sum = 0
    for i in range(16):
        sum += delta                    # ❌ delta 累加方式错误
        R += ((L<<4)^(L>>5)) + L ^ (sum + keys[i])  # ❌ 缺少 step2/step3
        L += ((R<<4)^(R>>5)) + R ^ (sum + keys[i])  # ❌ 结构错误
    return L, R
# 这个永远不会得到正确答案
```

正确的结构需要包含：
- `step2(rol32(v0, amount))` 在 v1 路径
- `step3(t, param)` 非线性混合
- delta 每个 BB 累加一次（不是每轮）
- S-Box 混入在特定轮次
