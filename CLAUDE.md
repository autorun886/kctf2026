# CLAUDE.md
These rules apply to every task in this project unless explicitly overridden.Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.
## Rule 1 — Think Before CodingState assumptions explicitly. If uncertain, ask rather than guess.Present multiple interpretations when ambiguity exists.Push back when a simpler approach exists.Stop when confused. Name what's unclear.
## Rule 2 — Simplicity FirstMinimum code that solves the problem. Nothing speculative.No features beyond what was asked. No abstractions for single-use code.Test: would a senior engineer say this is overcomplicated? If yes, simplify.
## Rule 3 — Surgical ChangesTouch only what you must. Clean up only your own mess.Don't "improve" adjacent code, comments, or formatting.Don't refactor what isn't broken. Match existing style.
## Rule 4 — Goal-Driven ExecutionDefine success criteria. Loop until verified.Don't follow steps. Define success and iterate.Strong success criteria let you loop independently.
## Rule 5 — Use the model only for judgment callsUse me for: classification, drafting, summarization, extraction.Do NOT use me for: routing, retries, deterministic transforms.If code can answer, code answers.
## Rule 6 — Token budgets are not advisoryPer-task: 4,000 tokens. Per-session: 30,000 tokens.If approaching budget, summarize and start fresh.Surface the breach. Do not silently overrun.
## Rule 7 — Surface conflicts, don't average themIf two patterns contradict, pick one (more recent / more tested).Explain why. Flag the other for cleanup.Don't blend conflicting patterns.
## Rule 8 — Read before you writeBefore adding code, read exports, immediate callers, shared utilities."Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.
## Rule 9 — Tests verify intent, not just behaviorTests must encode WHY behavior matters, not just WHAT it does.A test that can't fail when business logic changes is wrong.
## Rule 10 — Checkpoint after every significant stepSummarize what was done, what's verified, what's left.Don't continue from a state you can't describe back.If you lose track, stop and restate.
## Rule 11 — Match the codebase's conventions, even if you disagreeConformance > taste inside the codebase.If you genuinely think a convention is harmful, surface it. Don't fork silently.
## Rule 12 — Fail loud"Completed" is wrong if anything was skipped silently."Tests pass" is wrong if any were skipped.Default to surfacing uncertainty, not hiding it.

## Rule 13 — [autoctf] 日志
所有关键节点必须输出以 `[autoctf]` 为前缀的日志。关键节点包括但不限于：
- 模块实现开始/完成
- 编译/构建结果
- 测试通过/失败
- 蜜罐验证结果
- Flag 预计算完成
- 阶段性里程碑达成
格式：`[autoctf] <简要描述>`。日志应出现在代码注释、构建脚本输出、以及对话中的 checkpoint 总结中。

master plan is 2026KCTF_v4.md and 2026KCTF_CFG.md
task list is TODO.md
progress log is PROGRESS.md — 每次新会话开头先读此文件，结束时追加进展

## 构建注意事项
- **编译命令**：在项目根目录 `D:\KCTF2026\` 下运行 `./gradlew assembleDebug`（bash）或 `gradlew.bat assembleDebug`（cmd）
- **不要用 IDE 的静态分析结果判断编译错误**：Windows 上的 clangd 找不到 `jni.h`、`unistd.h`、`sys/time.h` 等 Android NDK 头文件，这些全是误报，以 `gradlew` 实际输出为准
- **APK 产物路径**：`app/build/outputs/apk/debug/app-debug.apk`
- **目标 ABI**：arm64-v8a（主要），armeabi-v7a / x86 / x86_64 同时构建
