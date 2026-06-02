# PROGRESS.md — 跨会话进度日志

> 每次关键进展记录一行。新会话开头读此文件即可接上上下文。

---

## 2026-05-18

- 项目初始化：Android Gradle 骨架建立（API 29+, JNI + CMake）
- 规范文档完成：2026KCTF_v4.md（主设计）+ 2026KCTF_CFG.md（控制流图）
- TODO.md 任务清单完成（8 Phase，完整依赖关系）
- CLAUDE.md 补充 Rule 13（[autoctf] 日志前缀）
- 测试向量文件创建：test_vectors.h
- 当前状态：零业务代码，准备进入 Phase 2（核心密码学实现）

---

## 2026-05-19

- 设计审查：稳定性、flag 唯一性、叙述清晰度
- **验证机制重构**：SHA-256 替换为 soKey 加密的状态直接比对（ENC_EXPECTED_STATE ^ soKey）
  - 原因：SHA-256 使 pipeline 不可逆/不可约束求解，导致题目需要暴力破解
  - 新机制：选手通过 Z3 约束求解，难度来自逆向+建模而非计算不可行性
  - 常量时间比较（volatile diff |= ...）防时序侧信道和 hook
- **轮密钥动态反馈弱化为仅后 4 轮**：`if (round >= 12) dynamic_key ^= state[0:4]`
  - 原因：全 16 轮反馈导致 Z3 约束规模不可控（256 次 S-Box 联合求解）
  - 新设计：前 12 轮静态（Z3 可分段），后 4 轮动态（64 次 S-Box，可控）
  - 与"后 4 轮动态 S-Box"对齐，概念统一
- **蜜罐 B 统一为无分支版本**：`penalty = (policy != 3) * 4; rounds = 12 - penalty`
- **蜜罐 C 修复**：adjust_logging 首次调用缓存结果，避免 4 次重复 I/O 和竞态
- **唯一性论证补充**：expand_key_material 单射性证明（输入空间 < 状态空间 + ARX 双射）
- **叙述歧义修复**：sbox_sel 写法统一、蜜罐 A vs honey_aes_path 关系澄清、material 布局注释
- 三份文档同步更新：2026KCTF_v4.md / 2026KCTF_CFG.md / TODO.md

---

---

## 2026-05-20

- **方案修正**：PROGRESS.md 2026-05-18 记录"方案确定：方案 B"有误，实际两方案均需实现
- TODO.md 重构：拆分为 Phase 2A（方案 A 显式修复）+ Phase 2B（方案 B 隐式修复），共享 Phase 1/3/4/5/7/8，各自独立 Phase 6A/6B
- WRITEUP_EXPECTED.md 补充方案 A 完整解题路径（BB 地址反推 → 双射约束 → 明密文对约束 → IO 对约束）
- 两方案 flag 结构均为 25 字节，Base64 编码提交
- **Phase 1 完成**：MainActivity UI（EditText + Button + Toast）、deriveNativeKey()（CRC32+LCG）、JNI 声明
- **Phase 2B 核心完成**：key_expand.c（ARX 12轮+soKey双向验证）、sbox_gen.c（Fisher-Yates）、spn_round.c（16轮SPN+蜜罐A/D）、init.c（检测点A）、ipc_verify.c（占位）、jni_entry.c
- **Phase 2A 占位完成**：repair_cfg/sbox/constants/semantics/core_compute/jni_entry_a 均为占位，Phase 2A 后续填充
- **蜜罐 A/B/C/D 框架就位**：A（g_render_mode，显式分支）、B（g_cache_policy，无分支）、C（g_log_verbosity，显式分支）、D（g_frame_budget_ns，无分支）
- **BUILD SUCCESSFUL**：`./gradlew assembleDebug` 四架构全部通过（arm64-v8a / armeabi-v7a / x86 / x86_64）
- CLAUDE.md 补充构建注意事项（gradlew 编译，IDE 误报忽略）

---

## 2026-05-20（续）

- **Phase 6A 完成**：
  - extract_bb_addrs.py 自动提取 BB 地址（BB0=0x351C, BB2_TBZ=0x3624, BB4=0x36E8, BB6_ADR=0x379C, BB7=0x37A4）
  - precompute_a.py 计算 flag（b64: CAAAAAEHAAAAnKSLqrl5N57ewK3eB0ITNw==）
  - ENC_EXPECTED_STATE_A 填入 jni_entry_a.c；VALID_BB_OFFSETS 填入 repair_cfg.c
  - BUILD SUCCESSFUL
- **注意**：当前地址为 Debug build，Release build 需重新运行 extract_bb_addrs.py

---

## 2026-05-21

- **Phase 6B 完成**：
  - `deriveNativeKey` 改为只读 `.text` section（非整个 PT_LOAD），避免 `.rodata` 常量影响 soKey
  - `EXPECTED_SOKEY_CHECK` 改为 `static volatile const`（放 `.rodata`，不内联到 `.text`）
  - 收敛后：soKey=`2364a252...`，EXPECTED_SOKEY_CHECK=`0x2338f89b`
  - ENC_EXPECTED_STATE（方案 B）= `B21EC6E6E74F8DFEB769458...`
  - ENC_EXPECTED_STATE_A（方案 A）= `C7B66B881FB68FF946545A5B4E449622`
- **Phase 7 验证通过**：
  - 方案 A：正确 flag PASS，错误 flag FAIL
  - 方案 B：正确 flag PASS，错误 flag FAIL，错误 soKey FAIL
  - BUILD SUCCESSFUL
- **方案 A flag (b64)**：`oYMeAAEHAAAAImSiUrl5N57ewK3eB0ITNw==`
- **方案 B flag (b64)**：`S0NURjIwMjZfQl92MV8yMDI2X0FVVE9DVA==`

---

## 2026-05-26

- **Phase 5 完成**：
  - strings.c：7 个检测字符串加密（/proc/self/status、TracerPid:、/proc/self/maps、frida/xposed/substrate/gadget）
  - init.c / sbox_gen.c 改用 get_string() 调用
  - resolver.c：8 个系统函数名加密（clock_gettime/fopen/fgets/fclose/open/read/close/mprotect），dlsym 动态解析，key_expand.c 和 sbox_gen.c 改用 get_func_by_id()
  - 花指令：expand_key_material / generate_sbox / spn_round / nonlinear_feedback / honey_tea_path / honey_aes_path / repair_cfg 各加一处 cmp xzr,xzr + b.ne + .word 垃圾字节
  - CMakeLists.txt 添加 dl 链接
  - BUILD SUCCESSFUL

- **Phase 8 完成**：
  - minifyEnabled + isShrinkResources 启用
  - ProGuard 规则保留 JNI 入口和 deriveNativeKey
  - Release 构建 + 常量收敛（3 轮迭代）：
    - CRC32(.text) = abc8dac9（稳定）
    - soKey = 60b8d70426dce417a87c6c2488eee575
    - EXPECTED_SOKEY_CHECK = 0x71130129
    - BB 地址：BB0=0x2db0, BB2_TBZ=0x2f84, BB4=0x3118, BB6_ADR=0x32a8, BB7=0x32b0
  - kctf2026.jks 生成，APK 签名
  - **app-release.apk**：`app/build/outputs/apk/release/app-release.apk`（2.1 MB）
  - verify.py 两方案全部通过（PASS/FAIL 均符合预期）

- **最终 flag**：
  - 方案 A (b64): `5gEAAAEEAAAAYbjXBLl5N57ewK3eB0ITNw==`
  - 方案 B (b64): `S0NURjIwMjZfQl92MV8yMDI2X0FVVE9DVA==`
  - 50-byte 交错 (b64): `5ksBQwBUAEYBMgQwADIANgBfYUK4X9d2BDG5X3kyNzCeMt42wF+tQd5VB1RCTxNDN1Q=`

---

---

## 2026-05-27

- **T1 约束对实现**：
  - repair_constants.c：填入 3 组 KPT/KCT 明密文对，XTEA 验证，不匹配→蜜罐
  - repair_semantics.c：填入 8 组 KIN/KOUT IO 对，s2_check/s3_check 验证，不匹配→蜜罐
  - KCT/KOUT 值嵌入 .text 比较指令导致 CRC 随值变化 → 收敛振荡（3 个 CRC 值循环）
- **T2 方案 A 蜜罐 B/D**：
  - repair_constants.c：独立 clock_gettime 时间差检测，penalty=8 额外 LCG 轮
  - repair_semantics.c：独立 BRK 指令扫描，budget_flag 翻转 step2_amount bit0
- **T3 花指令**：
  - repair_sbox.c：0xBAADF00D
  - repair_constants.c：0xDEADC0DE
  - repair_semantics.c：0x0BADC0DE
- **收敛振荡修复**：KCT/KOUT 比较改用 volatile 局部变量读取，阻止编译器生成值相关指令序列
  - repair_constants.c：`volatile uint32_t kct0/kct1`
  - repair_semantics.c：`volatile uint32_t kout`
  - jni_entry_a.c：ENC_EXPECTED_STATE_A 改为 `volatile const`
- **BUILD SUCCESSFUL**（Debug + Release）
- **待完成**：T6 静态/设备验证 → T7 发布准备

---

## 2026-05-27（续2）

- **converge.py 重写完成**：自动化全流程脚本
  - 流程：Build → Extract .text CRC → BB地址 → 正向模拟 → 更新源文件 → Rebuild → 循环至收敛 → 验证
  - 修复：KCT/KOUT 比较使用 volatile 局部变量 → 阻止编译器生成值相关指令
  - 修复：EXPECTED_SOKEY_CHECK 正则替换（完整 0x...u 值匹配，避免拼接）
  - 全部 log 使用 `[autoctf]` 前缀 + ASCII-safe 英文
  - 用法：`py -3 converge.py [--release|--debug] [--dry-run] [--max-iter N]`
- **收敛完成**（4 轮迭代）：
  - CRC32(.text) = `e9bd9f2e`（稳定）
  - soKey = `280d010509a3b7f26e115fe50e198834`
  - EXPECTED_SOKEY_CHECK = `0xb6856aa6u`
  - step3_bits = 23
  - BB 地址：`BB0_BRANCH=0x1b30`, `BB6_ADR=0x2028`
  - KCT/KOUT 填入，repair_constants/semantics 验证逻辑就位
- **verify.py 全通过**：
  - 方案 B：正确flag PASS，错误flag PASS，错误soKey PASS
  - 方案 A：正确flag PASS，错误flag PASS
  - 50-byte 交错：PASS
- **T1+T2+T3 完成**：
  - T1: KPT/KCT + KIN/KOUT 约束对就位
  - T2: 方案 A 蜜罐 B（时间差）+ D（BRK扫描）就位
  - T3: 三文件花指令就位（0xBAADF00D / 0xDEADC0DE / 0x0BADC0DE）
- **最终 flag**：
  - 方案 A (b64): `AgAAAAEEAAAAKQ0BBbl5N57ewK3eB0ITNw==`
  - 方案 B (b64): `S0NURjIwMjZfQl92MV8yMDI2X0FVVE9DVA==`
  - 50-byte  (b64): `AksAQwBUAEYBMgQwADIANgBfKUINXwF2BTG5X3kyNzCeMt42wF+tQd5VB1RCTxNDN1Q=`
- **脚本交付物**：
  - `converge.py` — 全自动收敛脚本（Build + Compute + Update + Verify）
  - `verify.py` — 端到端验证（需 .so 路径参数）
  - `precompute_a.py` / `precompute_b.py` — 单方案预计算
  - `extract_bb_addrs.py` — BB 地址提取
  - `make_flag.py` — flag 交错合并

---

## 2026-05-27（续3）

- **flag 唯一性分析**：
  - 方案 B：200-bit 输入 vs 128-bit 输出约束，理论上 ~2^72 个有效 flag，Z3 找到的解不一定是预期 flag
  - 方案 A：flag[9:13]（S-Box seed）双射约束不足，约 37% 随机 seed 满足，有效 seed ~1.6 亿
  - TODO 中 T4（strings 多密钥）和 T5（ipc_verify）均不能解决唯一性问题：
    - strings.c 不参与 final_state 验证链
    - ipc_verify 的 material[112:128] 在 key_schedule 中从未被读取（死数据）
- **新增 T4（flag 唯一性修复）**，标记为 🔴 阻塞题目公平性：
  - T4.1 方案 B：加第二次 SPN 运行（IV2 + ENC_EXPECTED_STATE2），总约束 256 bit > 200 bit，唯一性数学保证
  - T4.2 方案 A：repair_sbox 末尾加 3 字节已知对验证（SBOX_CHECK[3]），与 KPT/KCT 同质，不降低难度
  - 两处改动均为 .rodata，不影响 .text CRC，无需重新收敛 soKey
- **待完成**：T4 实现 → T6 验证 → T7 发布

---

## 2026-05-27（续4）

- **难度评估与解题流程梳理**：
  - 方案 A：2-4h，修复链结构清晰，每步有明确已知对约束，无需 Z3
  - 方案 B：4-8h，唯一可行路径是 Z3 正向建模（SPN 不可逆）
  - 两方案串行（A 是 B 的前置），合计 6-12h，定位合理
- **发现两个设计 bug**：
  - NL_POWER {3,5,7,11} 中 power=3/5 不是 GF(2^8) 双射（gcd(3,255)=3, gcd(5,255)=5）
    → Z3 遇到多解分支，求解变慢但无技术含量提升
  - MDS[1]/MDS[2] 行列式为 0，不可逆（奇异矩阵）
    → 客观上封死了 SPN 逆推路径，保留不动
- **新增 T4.3**：将 NL_POWER 改为全双射幂次 {7,11,13,23}
  - 改动：spn_round.c 第 62 行，4 字节
  - 效果：Z3 求解时间从 4-8h 降至 1-3h，不降低难度
  - 需要重新收敛（改变 .text）
- **新增 WRITEUP_IDEAL.md**：完整理想解题流程文档
  - 包含两方案的逐步求解路径、Z3 建模伪代码、难度定位、非预期路径说明
- **当前最高优先任务**：T4.3 → T4.1 → T4.2 → 收敛 → 验证 → 发布

---

## 2026-05-28

- **CRC 振荡根因修复**：
  - 根因：KCT/KOUT 为 `static const`，编译器用 MOVZ/MOVK 将值内联到 .text，导致值变化→CRC变化→soKey变化→值变化的振荡循环
  - 修复：KCT（repair_constants.c）和 KOUT（repair_semantics.c）改为 `static volatile const`，编译器改用 LDR 从 .rodata 加载，值不再进入 .text
  - 同步修复：SBOX_CHECK 比较改用 volatile 局部变量（sc0/sc1/sc2），converge.py 重新启用 SBOX_CHECK 更新
  - converge.py 正则同步更新（匹配 `volatile const` 声明）
- **T4 全部完成**（T4.1 双IV + T4.2 SBOX_CHECK + T4.3 NL_POWER）
- **收敛完成**（2 轮迭代）：
  - CRC32(.text) = `b3af5754`（稳定）
  - soKey = `2e4bbe730e45bbe0e5afe89317e2a336`
  - EXPECTED_SOKEY_CHECK = `0xaea59ffeu`
  - BB0_BRANCH=0x1d8c, BB6_ADR=0x2284
- **verify.py 全通过**：
  - 方案 B：IV1 PASS，IV2 PASS，错误flag PASS，错误soKey PASS
  - 方案 A：正确flag PASS，错误flag PASS
- **最终 flag**：
  - 方案 A (b64): `AgAAAAEEAAAAL0u+c7l5N57ewK3eB0ITNw==`
  - 方案 B (b64): `S0NURjIwMjZfQl92MV8yMDI2X0FVVE9DVA==`
  - 50-byte 交错 (b64): `AksAQwBUAEYBMgQwADIANgBfL0JLX752czG5X3kyNzCeMt42wF+tQd5VB1RCTxNDN1Q=`
- **待完成**：T6 静态/设备验证 → T7 发布准备

---

## 2026-05-31

- **代码审查与重构**：
  - verify.py NL_POWER 修复：`[3,5,7,11]` → `[7,11,13,23]`（与 spn_round.c 同步）
  - converge.py 末尾新增 verify.py 常量自动同步
  - converge.py 删除对已死 jni_entry_a.c 的更新逻辑
  - CMakeLists.txt 移除空壳文件 sha256.c / utils.c

- **难度提升实施（M1-M4 + M6 + M8）**：
  - **M1 FLAG_B 改随机字节**：25 字节固定随机值，阻止格式猜测
  - **M2 ARX 轮数 12→16**：key_expand.c + 所有 Python 脚本同步
  - **M3 动态轮扩展 round>=12 → round>=8**：静态部分 12→8 轮，Z3 联合约束翻倍
  - **M4 反 Unicorn（蜜罐 E）**：/proc/self/auxv AT_HWCAP 检测，无分支污染 round_key
  - **M8 多时间点采样（蜜罐 B2）**：每 4 轮 clock_gettime，单步调试必触发
  - **M6 AI 蜜罐假后门**：DEBUG_MAGIC + "dev_bypass_v2_enabled"
  - BUILD SUCCESSFUL
- **待完成**：运行 `converge.py --release` 重新收敛 → 验证 → 发布

---

## 2026-06-02

- **真机验证与 Bug 修复**：
  - 花指令 `b.ne` → `b.eq`（修复 SIGILL 崩溃）
  - deriveNativeKey 重写：从 APK ZipFile 读取 .so（修复 Android 12+ 内嵌加载）
  - repair_cfg 改为纯验证模式（不再 mprotect 写 .text）
  - calibrate_frame_budget 中 `__executable_start` → `expand_key_material` 函数地址
  - 蜜罐 E 改用 `getauxval()`（修复 /proc/self/auxv 权限问题）
  - 蜜罐 B2 `g_perf_samples` 每次调用重置（修复跨调用累积误触发）
  - 输入格式改为 hex（100 字符直接输入）
  - Pixel 6 真机验证通过

- **反调试加固**：
  - 蜜罐 A2：持续 TracerPid 检测（SPN 执行期间）
  - 蜜罐 F：inline hook 检测（libc 函数头 B/LDR 检测），改用 get_func_by_id
  - 蜜罐 C 增强：大匿名可执行内存段 >2MB 检测
  - 反 Unicorn：中间状态 CRC32 混入后 8 轮 round_key
  - 动态函数调用：去掉 PLT fallback（fopen/fgets/fclose/clock_gettime）
  - 花指令升级：输入驱动不透明谓词（g_opaque = input[0]，双 volatile 读取比较）

- **ARX 轮数调整**：
  - 16 轮 → Z3 24h 超时（不可解）
  - 14 轮 → Z3 10.3 min（可解）
  - 12 轮 → Z3 8.5 min（稳妥）
  - 当前保留 12 轮

- **Z3 可解性分析**：
  - 纯 ARX 逆向（已知 material 96 字节）：12 轮 = 8.5 min ✓
  - 选手只知 soKey check（32-bit 约束）：Z3 2h 超时 ✗
  - 选手知 seeds + soKey check（160-bit 约束）：待验证（常量同步问题）
  - **核心问题**：Fisher-Yates 不可符号化，选手无法把完整 SPN 放进 Z3
  - **解决方案**：暴露 sbox_seeds[4] 给选手（16 字节），使 S-Box 可预计算

- **当前状态**：
  - Release APK 真机验证通过（12 轮 ARX）
  - Z3 求解路径设计中：需要暴露 seeds 并验证选手可在合理时间内求解
  - 常量需要重新同步（converge.py ESC 与 test 脚本不一致）

- **待完成**：
  1. 确定 seeds 暴露方式并实现
  2. 重新收敛
  3. 验证选手 Z3 路径（seeds known → 求解时间）
  4. 真机验证
  5. 更新文档和 flag


