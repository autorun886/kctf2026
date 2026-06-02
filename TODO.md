# 2026 KCTF 剩余任务

> 更新于 2026-06-02

---

## 🔴 阻塞发布

### T1：Z3 可解性保证

**问题**：选手无法符号化 Fisher-Yates（255 次 URem + swap），导致完整 SPN 无法放进 Z3。仅用 soKey check（32-bit）约束 ARX 时 Z3 2h 超时。

**方案**：暴露 sbox_seeds[4]（16 字节）给选手。

**实现**：
1. 在 jni_entry.c 或 key_expand.c 的 .rodata 中放置 `KNOWN_SEEDS[4]` 数组
2. converge.py 收敛后自动填入正确值
3. 选手约束变为：ARX(flag)[80:96] == known_seeds (128-bit) + ARX(flag)[60:64] == known_rk15 (32-bit)
4. 160-bit 约束，Z3 预计 5-10 min 可解
5. 解不唯一时选手用 Python 正向跑 SPN 验证（秒级）

**验证**：跑 test_seeds_known.py（需先同步常量）

### T2：常量同步

**问题**：ARX 从 16 轮改回 12 轮后，converge.py 内部计算的 EXPECTED_SOKEY_CHECK 与 test 脚本中的硬编码值不一致。

**修复**：
1. 确认 key_expand.c 当前是 12 轮
2. 确认所有 Python 脚本的 ARX 循环是 `range(12)`（注意不要误改 SPN 的 `range(16)`）
3. 运行 `converge.py --release` 重新收敛
4. 用收敛后的常量更新 test_seeds_known.py

### T3：重新收敛 + 真机验证

依赖 T1 + T2 完成后：
1. `py -3 converge.py --release`
2. `adb install` + 输入 hex flag
3. 确认 Toast = LENGTH_LONG

---

## 🟡 发布前

### T4：Z3 求解验证

用最终常量跑 test_seeds_known.py，确认：
- Z3 在 30 分钟内返回 sat
- 解出的 flag 与正确 flag 一致（或通过 SPN 正向验证）

### T5：文档更新

- TECH_SUMMARY.md：补充 seeds 暴露机制
- SOLUTION.md：更新选手 Z3 建模路径
- SOLUTION_AI.md：补充 "AI 不会告诉你 seeds 在哪"
- DESIGN_FINAL.md：补充 Z3 可解性设计

### T6：最终 git 提交

---

## 🟢 可选

### T7：花指令抗 D810

当前花指令（双 volatile 读取 g_opaque 比较）被 D810 反编译优化去除。
可升级为数学恒等式不透明谓词，但对 KCTF 来说 D810 用户极少。

### T8：strings.c 多密钥方案

当前 7 个检测字符串用单一 XOR 方案。可升级为 6 种 key_source。
对题目核心难度影响很小。

---

## 执行顺序

```
T2（常量同步）→ T1（seeds 暴露）→ T3（收敛+真机）→ T4（Z3 验证）→ T5（文档）→ T6（提交）
```
