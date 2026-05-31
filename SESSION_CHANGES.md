# 2026-05-31 会话调整点记录

> 本文档记录本次会话对项目的所有调整，供后续参考。

---

## 一、代码审查与重构

| 调整 | 文件 | 说明 |
|------|------|------|
| verify.py NL_POWER 修复 | verify.py | `[3,5,7,11]` → `[7,11,13,23]` |
| converge_b.py NL_POWER 修复 | converge_b.py | 同上 |
| FLAG_B 同步 | converge_b.py, precompute_b.py | ASCII → 随机字节 |
| converge.py 自动同步 verify.py | converge.py | 收敛后自动更新 verify.py 的硬编码常量 |
| converge.py 删除 jni_entry_a.c 更新 | converge.py | 死代码，不再维护 |
| CMakeLists 移除空壳 | CMakeLists.txt | sha256.c, utils.c 移除 |
| ProGuard 清理 | proguard-rules.pro | 删除不存在的 onVerifyClick 规则 |
| Layout hint 更新 | activity_main.xml | "Base64-encoded flag" → "Enter hex flag (100 chars)" |
| Debug 日志移除 | MainActivity.java | 移除所有 Log.d/Log.e 调用 |
| 蜜罐函数防 strip | tea_impl.c, aes_impl.c | 加 `__attribute__((used))` |

---

## 二、难度提升

| 编号 | 调整 | 效果 |
|------|------|------|
| M1 | FLAG_B 改为随机字节 | 防格式猜测 |
| M2 | ARX 轮数 12→16 | Z3 约束规模 +33% |
| M3 | 动态轮阈值 round>=12 → round>=8 | Z3 联合约束翻倍 (64→128 次 S-Box) |
| M4 | 蜜罐 E (getauxval HWCAP) | 反 Unicorn 模拟 |
| M8 | 蜜罐 B2 (多时间点采样) | 反单步调试 |
| M6 | AI 假后门 (check_debug_bypass) | 误导 AI 分析 |
| — | 蜜罐 F (inline hook 检测) | 反 Frida/Xposed |
| — | 蜜罐 C 增强 (大匿名内存 >2MB) | 反 Frida 注入 |
| — | 蜜罐 A2 (持续 TracerPid) | 反运行时 attach |
| — | 中间状态 CRC32 混入 | 反 Unicorn 部分模拟 |

---

## 三、真机验证修复

| Bug | 原因 | 修复 |
|-----|------|------|
| SIGILL 崩溃 | 花指令 `b.ne` 逻辑反了 | → `b.eq` |
| soKey 全零 | Android 12+ APK 内嵌加载，/proc/self/mem 无 section headers | → 从 APK ZipFile 读取 .so |
| SIGSEGV (repair_cfg) | `__executable_start` 对 .so 无效 + mprotect RWX 被拒 | → 改为纯验证模式 |
| SIGSEGV (calibrate_frame_budget) | `__executable_start` 对 .so 无效 | → 改用 `expand_key_material` 函数地址 |
| 蜜罐 E 误触发 | `get_func_by_id` 返回异常 + /proc/self/auxv 权限 | → 改用 `getauxval()` |
| 蜜罐 B2 跨调用累积 | `g_perf_samples` 不重置 | → `spn_encrypt` 入口重置 |
| get_session_token 崩溃 | Release 优化导致栈布局异常 | → 移除（功能不影响验证） |

---

## 四、输入格式变更

- **旧**：Base64 编码（68 字符，有 padding 冗余）
- **新**：Hex 编码（100 字符，无歧义）
- **原因**：Base64 的 padding 位冗余导致多个编码对应同一解码结果

---

## 五、动态函数调用加固

| 调整 | 说明 |
|------|------|
| key_expand.c adapt_cache_strategy | 去掉 clock_gettime fallback |
| key_expand.c 蜜罐 F | dlsym 明文 → get_func_by_id |
| sbox_gen.c adjust_logging | 去掉 fopen/fgets/fclose fallback |
| spn_round.c check_render_sync | 直接 open → get_func_by_id(4/5/6) |
| spn_round.c sample_perf_counter | 直接 clock_gettime → get_func_by_id(0) |

**效果**：PLT 导入从 16 个减少到 13 个，`fopen/fgets/fclose/mprotect` 从 PLT 中消失。

---

## 六、花指令升级

- **旧**：`cmp xzr, xzr; b.eq 1f; .word 0x...` — IDA 直接识别为恒真跳转，优化掉
- **新**：`g_opaque = input[0]; cmp _a, _b; b.eq 1f; .word 0x...` — 两次 volatile 读取 g_opaque 比较
- **效果**：
  - IDA 不知道 g_opaque 的值（来自用户输入），必须考虑两条路径
  - 选手不能 patch g_opaque → input[0] 参与方案 A 验证
  - Patch .text → soKey CRC 变化 → 全链路失败

---

## 七、converge.py 增强

| 功能 | 说明 |
|------|------|
| 自动同步 verify.py | 收敛后更新 ENC_B/ENC_A/FLAG_A/BB6_ADR_OFF/EXPECTED_SOKEY_CHECK |
| 自动更新 repair_cfg.c BB 地址 | volatile const 变量，不影响 .text CRC |
| 输出格式改为 hex | 与 app 输入格式一致 |
| FLAG_B 定义为常量 | 顶部定义，所有引用统一 |

---

## 八、最终状态

| 项目 | 值 |
|------|-----|
| CRC32(.text) | `d0b82932` |
| soKey | 从 APK 动态计算 |
| Flag (hex) | `027a00e3001b009401d2045600f8000c004146b72629fb8eb963b9a579df37109e4bdec8c072ad3dde96070f42e4135837ad` |
| APK | `app/build/outputs/apk/release/app-release.apk` |
| 真机验证 | Pixel 6 (Android 12+) PASS |
| 蜜罐数量 | 8 层 (A/A2/B/B2/C/D/E/F) |
| IDA 可见函数 | 9 个用户函数 |
| 预计解题时间 | 10-16h |
