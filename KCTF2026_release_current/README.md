# KCTF2026 当前发布包

本目录包含当前已测试的发布 APK，以及与该构建对应的公开 WP、设计说明和校验信息。

## 文件

- `KCTF2026.apk`：当前发布 APK。
- `flag-keygen.py`：面向公开约束的 `material[8:16]` 求解辅助脚本。
- `DESIGN.md`：题目设计、抗逆向和反 AI 说明。
- `WRITEUP.md`：选手视角的恢复路径和当前答案。
- `SHA256SUMS.txt`：发布文件校验和。

## 当前 APK

```text
SHA256(KCTF2026.apk) = 21f932aa6222a37ffc4183861017794c45c3e07a5eb88a7b9050e044256e763f
guard_crc32         = 3e0695ce
soKey               = 870573e5f5c63d52862dbd05ab3d9494
```

该 APK 已在真实 arm64 Android 设备上安装测试；当前 100 个十六进制字符的输入会返回
`Correct! Flag accepted.`。

## 辅助脚本用法

快速检查公开约束，不运行 SMT：

```bash
python3 flag-keygen.py --self-test
```

运行隐藏 material 通道模型：

```bash
python3 flag-keygen.py --timeout-ms 600000 --verbose KCTF2026.apk
```

该辅助脚本刻意不打印最终 flag。它只读取 APK，派生 `soKey`，校验编码后的 oracle/material 公开约束，然后建模求解 `material[8:16]`。

公开脚本只保留一个后端：Bitwuzla + QF_BV。它假设选手已经把 native 中围绕 lane-hint 检查的 MBA 外壳还原成紧凑语义，然后求解 ARX 填充逆向和 46 条已恢复的 Q46 约束。

## 求解耗时

求解耗时取决于 CPU、内存和 Bitwuzla 版本。参考测试中，还原 MBA 后约数分钟得到第一候选；未还原 MBA 的 raw 模型在 20 分钟超时内未得到候选。建议使用 `--timeout-ms` 按本机资源设置上限。

Python 依赖：

```bash
python3 -m pip install bitwuzla
```

## 预期自检输出

```text
apk_sha256_ok=True
guard_crc32_ok=True
soKey_ok=True
oracle_head_ok=True
lane_ctx=0x129b4a86
material_lane_hint=0x016eff8c39c23
known_a_share=0xd7
```

当前 oracle 的 dlsym/SVC 后备映射、XOR 加载器和蜜罐耦合设计见 `DESIGN.md`；完整恢复路径和已测试的最终输入见 `WRITEUP.md`。
