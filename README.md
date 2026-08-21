# 看雪 KCTF 2026 第六题：酉时·书院迷局

本仓库是看雪 KCTF 2026 第六题「酉时·书院迷局」的完整工程，包含 Android/Native 源码、可复现构建工具、最终发布 APK、公开求解辅助脚本及题解文档。

题目类型为 Android Native 逆向。选手提交 100 个小写十六进制字符，应用解码为 50 字节，并在 JNI 中将奇偶位拆成两条相互约束的 25 字节路径。核心考点包括 APK/ELF 完整性派生、受限控制流语义、ARX key material、动态 S-Box 与双 IV SPN，以及运行时检测对真实数据流的污染。

## 仓库结构

```text
.
├── app/                         Android 应用与 Native 题目源码
├── gradle/                      Gradle Wrapper 配置
├── KCTF2026_release_current/    当前发布包、公开 WP 与求解辅助脚本
├── BUILD.md                     编译、收敛和一致性验证说明
├── converge.py                  Native 常量收敛与 APK 后处理脚本
├── extract_bb_addrs.py          Native 基本块地址提取工具
├── flag_generate.py             构建后 flag 派生验证脚本
└── verify.py                    Python 侧方案 A/B 验证脚本
```

## 当前发布包

最终题目位于 [`KCTF2026_release_current/`](KCTF2026_release_current/README.md)：

```text
SHA256(KCTF2026.apk) = 21f932aa6222a37ffc4183861017794c45c3e07a5eb88a7b9050e044256e763f
ABI                     arm64-v8a
minSdk                  29
targetSdk               36
```

校验发布目录：

```bash
cd KCTF2026_release_current
sha256sum -c SHA256SUMS.txt
```

该 APK 已在真实 arm64 Android 设备上安装验证，正确输入会显示 `Correct! Flag accepted.`。

## 编译

普通 Gradle 构建：

```bash
./gradlew assembleRelease
```

本题的正式发布包还包含 Native 常量收敛、oracle patch、strip、zipalign 与重新签名流程。生成可发布 APK 应运行：

```bash
python3 converge.py --release --max-iter 10
```

完整环境要求、处理步骤及字节一致性校验见 [`BUILD.md`](BUILD.md)。

签名私钥和口令不在仓库中。普通构建可以生成未签名 release APK；需要安装或制作发布包时，请按 `BUILD.md` 配置自己的 keystore 和 `KCTF_*` 环境变量。

## 求解资料

发布目录内提供以下资料：

- [`DESIGN.md`](KCTF2026_release_current/DESIGN.md)：题目设计、混淆层与可解性边界。
- [`WRITEUP.md`](KCTF2026_release_current/WRITEUP.md)：选手视角的完整恢复路线，包含最终答案，阅读前请注意剧透。
- [`flag-keygen.py`](KCTF2026_release_current/flag-keygen.py)：保留的 Bitwuzla/QF_BV 建模脚本，用于求解隐藏的 `material[8:16]` 通道。

快速检查公开约束，不启动 SMT 求解：

```bash
python3 KCTF2026_release_current/flag-keygen.py --self-test
```

运行完整隐藏通道模型：

```bash
python3 -m pip install bitwuzla
python3 KCTF2026_release_current/flag-keygen.py \
  --timeout-ms 600000 --verbose \
  KCTF2026_release_current/KCTF2026.apk
```

脚本只读取发布 APK、派生 `soKey` 并求解 material 通道，不修改 APK，也不会打印最终 flag。
