# KCTF2026 出题说明

## 出题思路

题目的核心是“真实但不可组合”。每个检查点都是真实参与最终验证的逻辑，选手不能靠删分支、改返回值或 hook 某个单点拿到 flag；但这些真实信息又被拆成几类互相依赖的约束，不能直接组合成一个短路径。

输入是 100 个 hex 字符，解码为 50 字节后按奇偶位拆成两条 25 字节路径：

- `flagA` 负责修复/验证控制流、S-Box、常量和语义参数。
- `flagB` 负责驱动 ARX key schedule 和双 IV SPN 验证。
- `soKey` 从 APK 内 `libkctf.so` 的稳定 guard 代码段 CRC32 派生，并参与两条路径的目标状态加密。

设计目标不是堆反调试，而是让选手必须先理解数据流，再把静态恢复的信息、运行时完整性信息、约束求解结果拼起来。反 trace/hook/unicorn 只用于抬高直接动态提取中间值的成本，避免一条 hook 链绕开主逻辑。

## 题目特色

- 双路径交错输入：50 字节 flag 被拆成 `flagA[25]` 和 `flagB[25]`，单看 JNI 参数不会直接看到结构。
- `soKey` 绑定 APK：Java 从 APK 读取 `libkctf.so`，定位 `.kctfguard` 或 `.text` 中的 guard bytes，CRC32 后 LCG 扩展为 16 字节；native 再校验已加载 guard 的 CRC，patch `.text` 或换包会污染结果。
- 方案 A 是显式修复链：`repair_cfg -> repair_sbox -> repair_constants -> repair_semantics -> core_compute`，前一步结果会成为后一步输入。
- 方案 B 是隐式约束链：25 字节输入经 12 轮 ARX 扩展为 material，再派生 round keys、configs、sbox seeds 和 delta，最后跑两个不同 IV 的 16 轮 SPN。
- Oracle 只暴露 `material[80:96] + material[0:8] + tag[8]`，不再暴露 `material[8:16]`，阻断旧版直接 ARX 逆推捷径。
- 反动态分析点都接入真实计算：TracerPid、maps 扫描、HWCAP、inline hook、时序采样等检测结果会污染 round key、delta 或 oracle 解密，而不是只做退出。
- 蜜罐常量和函数名故意像 AES/TEA/ChaCha/SM4/SHA，但正确路径必须以 xref 和数据流为准。

## 选手视角题解

1. 定位入口：`MainActivity` 将输入 hex 解码为 50 字节，调用 `nativeProcessInput(byte[])`。JNI 中按奇偶位拆分为 `flagA` 和 `flagB`。
2. 恢复 `soKey`：逆向 `deriveNativeKey()`，从 APK 提取 `lib/arm64-v8a/libkctf.so`，解析 ELF section，计算 guard bytes 的 CRC32，再按 LCG 逻辑得到 16 字节 `soKey`。
3. 解方案 A：从 `repair_cfg.c` 和 `core_compute` 反推出 BB 偏移，恢复 `flagA[0:13]`；再跟进 `repair_sbox`、`repair_constants`、`repair_semantics`，得到 XTEA delta、LCG seed、step2/step3 参数。最终 `core_compute` 的输出要等于 `ENC_EXPECTED_STATE_A ^ soKey`。
4. 解方案 B：实现 `expand_key_material` 的 ARX 逻辑，恢复 `key_schedule` 对 round keys、configs、seeds、delta 的派生；实现 S-Box 生成和 SPN 16 轮正向模拟。
5. 建模求解：以 `flagB[25]` 为 200 bit 变量，加入 IV1 和 IV2 两组最终状态约束。Oracle 给出的 seeds 和 `material[0:8]` 可作为早期约束，但不能直接补齐 ARX 末态。
6. 组合 flag：将 `flagA` 和 `flagB` 逐字节交错，输出 50 字节 hex。

当前验证值：

- `guard_crc32 = 3e0695ce`
- `soKey = 870573e5f5c63d52862dbd05ab3d9494`
- `flagA = 0200000001832dbd05c70573e5b979379edec0adde07421337`
- `flagB = 7ae31b94d256f80c41b7298e63a5df104bc8723d960fe458ad`
- `flag = 027a00e3001b009401d283562df8bd0c0541c7b70529738ee563b9a579df37109e4bdec8c072ad3dde96070f42e4135837ad`

## Flag Generate 脚本

脚本位置：`flag_generate.py`

运行：

```bash
python3 flag_generate.py
```

也可以指定 APK：

```bash
python3 flag_generate.py app/build/outputs/apk/release/app-release.apk
```

脚本会从 APK 中读取 `libkctf.so` 派生 `soKey`，根据逆向恢复的 BB 偏移生成 `flagA`，再与求解得到的 `flagB` 交错输出最终 flag。
