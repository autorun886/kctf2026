# KCTF2026 IDA 视角 WP

本文按选手只拿发布版 APK 的视角写。所有数据源都应来自 APK、dex、`libkctf.so`、IDA 数据流或可控干净环境下恢复的 oracle 输出；不依赖源码中的私有中间量。

当前 IDA 主要定位如下。本文不记录发布构件指纹、哈希值或当前派生密钥的具体数值；这些由发布目录校验文件和辅助脚本验证。

```text
.text                          = 0x26a8..0x13d60
.kctfguard                     = 0x13d60..0x13dc0
JNI entry                      = 0x8260..0x8f90
B 侧校验器                    = 0x8f90..0xe818
  IDA 当前拆分为              = sub_8F90 + sub_C0D4
Q46 桥                         = sub_5998, 0x5998..0x5a38
Q46 真实分支                   = sub_5A38, 0x5a38..0x5fe8
OLLVM 蜜罐格                    = sub_2ED4, 0x2ed4..0x5528
oracle 加载器                  = sub_10E18, 0x10e18..0x12418
A 侧语义                       = core_compute/sub_126B8, 0x126b8..0x13008
material 分片加载器            = sub_F020, 0xf020..0xf32c
material 压缩器                = sub_F32C, 0xf32c..0x10414
```

## 1. 先建立完整依赖链

这题不能按“找到一个 compare，然后 patch/反解”处理。正确恢复链应当是：

```text
Java 输入格式
-> 50 字节奇偶拆 A/B
-> Java a() 解析 APK/ELF 元数据
-> native 动态消费 Java metadata，并短暂 patch Java m
-> 还原 `soKey` 和干净 profile padding
-> B 侧先展开 material，给 A 提供 material_share
-> A 侧 repair/semantic check，产出 a_share
-> oracle loader 解密 shellcode，恢复 seeds/head/tag
-> B 侧 material 分片、mid-tag、Q46 lane-hint、`fake_syndrome`
-> 化简 MBA，用 Bitwuzla 求 material[8:16]
-> 反演或建模 ARX 得到 flagB
-> 使用提交态 flagA，与 flagB 交错
-> Correct
```

后续每一节都要和这个链条对应。少还原其中任意关键点，最终通常不会在对应位置报错，只会合并成 `Wrong`。

容易出错的地方在于局部结论会互相污染：只看 Java 会漏 native metadata 副作用；只看 native 会低估 APK archive/profile 对 `soKey` 和 padding 的影响；只 dump oracle 会忽略干净/污染 share 和 encoded head；只做规则化 MBA 会把真实 Q46、mid-tag、`fake_syndrome` 和恒等包装混在一起；只求 `material[8:16]`，还缺 ARX 原像、A/B 交错和提交态 A lane。

WP 的目标是把每个必要依赖接回最终 `Correct`，不是提供单点捷径。

## 2. IDA 初筛

先确认哪些直接路线不存在。

导入表里有价值的信号包括：

```text
__open_2, read, close, dlsym, memcpy, opendir, readdir,
fopen, fread, fclose, closedir, strstr, strchr, getauxval,
clock_gettime, vsnprintf
```

没有直接导入 `mmap`、`munmap`、`mprotect`。oracle 映射路径要沿 dlsym/resolver 或 SVC 后备找，不能靠 PLT xref 秒定位。

字符串窗口中不应看到直接路线：

```text
frida, gum, TracerPid, /proc, mmap, munmap, mprotect,
material, oracle, flag, deriveNativeKey
```

连续字节搜索最终 flag、`soKey`、`material[8:16]`、oracle head/tag 也不应命中。能看到的表锚点例如 `byte_13e1`、`byte_13ed` 只是 material shard 解码入口，不是最终常量。

建议先在 IDA 中标注：

```text
sub_8260   JNI 输入拆分 + Java metadata/native profile + A/B 分发
sub_10E18  oracle 加载器：dlsym/SVC 后备映射 + 动态 XOR 载荷
sub_F020   material 期望值分片解码器
sub_F32C   material 压缩器
sub_5998   Q46 分发桥
sub_5A38   真实 Q46 lane-hint 主体
sub_2ED4   大型 OLLVM 蜜罐格
sub_126B8  A 侧语义/核心计算检查
```

少了这一步的后果：容易把 `sub_2ED4`、TEA-like、debug bypass、fake material decoy 当主线，模型会变大且方向错误。

## 3. Java 输入和 JNI 拆分

Java 只接受 100 个小写 hex，解码为 50 字节后调用 JNI。JNI 入口是：

```text
Java_com_autorun_kctf_MainActivity_nativeProcessInput @ 0x8260
```

native 把输入按奇偶拆成两条 25 字节 lane：

```text
flagA_submitted[i] = input[2*i]
flagB[i]           = input[2*i+1]
```

少了这一步的后果：把 50 字节当连续 flag，或者最终用 `flagA || flagB` 拼接，都会 Wrong。

## 4. 还原 APK 绑定 soKey

Java 短名方法 `a()` 会解析当前 APK 中的 `lib/arm64-v8a/libkctf.so`，定位 `.kctfguard` 和 `.text`，返回 32 字节 metadata。

具体 guard 校验值和 `soKey` 应由选手从当前 APK 自行派生。WRITEUP 不直接记录这些构件指纹或当前密钥数值。

注意：Java 字符串和 section 名不是明文常量池线索。需要把 Java 的 switch-case 字符串解密和 archive/profile 状态机整理出来。

更重要的是，Java 返回值不是 native 最终语义。native 会：

```text
meta[0:16] XOR sokey_share_mask -> soKey
复算 profile
复算运行时 guard/text 身份
校验失败则污染 soKey 或 g_java_archive_profile_delta
```

少了这一步的后果：直接用 Java 返回数组前 16 字节当 soKey 会错；重打包或 patch so 后不重新处理，也会在后续 A/B/oracle 上表现为 Wrong。

## 5. Java 静态 `m` 和 native 动态 profile

这是当前版本最容易造成“局部分析正确、组合后错误”的点。

Java 静态能看到类似：

```java
private static volatile int m = 0x5EED4A71;
```

Java profile 计算会用这个字段。但 native 在 `collect_java_archive_meta()` 的调用窗口里会：

```text
解码字段 token m/I
GetStaticFieldID
保存旧 m
写入 java_profile_runtime_seed()
调用 Java a()
恢复旧 m
```

因此准确说，不是 Java 字节码有两套逻辑，而是：

```text
静态 Java 返回值语义 != native 动态消费语义
```

动态有效 profile 使用短暂写入的运行时 seed。调用结束后 `m` 又恢复默认值，手动调用 Java `a()` 或静态跑 dex 很可能得到错误 profile。

少了这一步的后果：`g_java_archive_profile_delta` 非零，B 侧 padding 不再是干净路径下的 `0x5a`，后面 ARX material 全部偏掉。表现会像 B 算法或 solver 错。

## 6. B 侧 padding 和 ARX material

`flagB` 是 25 字节。干净路径下 native 后补 7 字节 `0x5a`，总共 32 字节，按四个小端 64 位 word 进入 12 轮 ARX material 扩展。

```text
input_to_arx = flagB || 5a5a5a5a5a5a5a
```

这个 padding 不是一个可以脱离 Java/native metadata 假设的常量。它受 Java profile delta 影响，只是在正确的干净路径下等于 `0x5a`。

少了这一步的后果：即使后续 `material[8:16]` 解对，也无法正确反演出 `flagB`。

## 7. Scheme A 和 `a_share`

提交态 A lane 先被依赖 `soKey` 的可逆布局层解码：

```text
flagA_submitted = a77a78ffc894367d1bf5bb3faab6e2f4db0070533de8b73443
flagA_plain     = 0200000001832dbd05c70573e5b979379edec0adde07421337
```

A 侧不是简单比较这 25 字节。解码后的字段会先参与一组受限跳转语义：`B`/`BL` 偏移、`TBZ` 条件边、`ADR` 目标和 dispatch 入口都必须落在题目允许的基本块关系上。之后这些字段继续修 S-box、round constants 和 step 参数，再进入 `core_compute` 生成语义状态。

这里容易误判成“自修改 CFG”或普通 patch 题，但更准确的理解是：A lane 在建模一组受限控制流可达性约束。字段值不只是期望常量，它们还决定哪些语义节点被认为可达、哪些跳转目标有效。期望状态还会混入 `soKey` 和 B 侧 material share，因此 A 侧和 B 侧不是两个完全独立 checker。

当前恢复出的基本块字段：

```text
BB0_BRANCH_OFF = 0xedb0
BB1_OFF        = 0xedb8
BB2_TBZ_OFF    = 0xef90
BB6_ADR_OFF    = 0xf2b4
BB7_ENTRY_OFF  = 0xf2bc
BB4_BRANCH_OFF = 0xf124
DEAD_BLOCK_OFF = 0xf128
BB5_OFF        = 0xf138
```

A 侧通过后给 B 使用：

```text
a_share = 0xd7
```

少了这一步的后果：oracle head/tag 和 B 期望遮罩都缺 `a_share`；只恢复 B 侧 material 不够。

## 8. Oracle loader 和 shellcode 输出

`sub_10E18` 是 oracle loader。当前 IDA MCP 下它反编译失败是正常现象；用反汇编看 dlsym/resolver、SVC 后备、载荷区间、间接调用和清理路径。

它的输出格式：

```text
seeds[16] || encoded_material_head[8] || tag[8]
```

注意第二段是 encoded material head，不是原始 `material[0:8]`。编码依赖 `seeds`、`soKey`、`a_share` 等上下文。

`.L_oracle_data` 也不是 32 字节明文。它使用 48 字节存储区，通过置换、查表、rotate 和索引掩码恢复输出。

少了这一步的后果：把 oracle 字节当明文 material 会错；只从 native 搜数组拿不到 seeds/head/tag 的完整来源。

## 9. 反调试和 hook 数据污染

oracle 和 native preflight 会采样：

```text
TracerPid
/proc/self/maps 中 frida/gum/xposed/gadget 痕迹
HWCAP
关键 libc 函数入口
mmap 前几条指令是否为 B/BL 或 LDR literal + BR/BLR 跳板
```

这些检测不是可随手 nop 的门禁，而是干净/污染 share。异常时可能仍然返回格式正确的 oracle data，但内容已污染。

这里不要只按 shellcode 保护理解。IDA 里更稳的判断方式是把运行时采样、Java/native metadata、oracle loader、MBA 包装、fake/decoy 和 OLLVM bait 都看成同一条数据流上的不同伪装层：

| 对象 | 真正用途 | 正确处理 | 常见错法 |
| --- | --- | --- | --- |
| Java/native profile 副作用 | 影响 `soKey` 消费和 B 侧 padding | 合并 Java 静态逻辑和 native 动态消费语义 | 手动跑 Java `a()` 或只看静态 `m` |
| 运行时环境采样 | 影响 key schedule、oracle 解码、期望遮罩、`fake_syndrome` | 还原干净 share，不把检测简单 nop 掉 | patch 检测后继续信任后续 material |
| oracle loader/payload | 产出 seeds、encoded head、tag 这些公开约束 | 确认输出来自干净路径，或静态还原 payload | hook 后 dump 一次就当成真 oracle |
| MBA 包装 | 隐藏 `lane_ctx`、`mid_tag`、Q46、`fake_syndrome` 等真实关系 | 化简恒等外壳，保留真实非线性约束 | 全量原样 SMT 超时，或全删导致漏约束 |
| OLLVM bait / fake decoy | 靠近真实桥和失败边，复用真实变量名 | 用可达性和最终 diff 数据流判断 | 因函数大、xref 多、变量名真实就当主线 |

正确顺序是：先确认数据来自干净路径，再切 material 检查；先证明蜜罐状态不被最终 diff 消费，再进入真实 Q46；先化简 MBA 恒等包装，再保留 `mid_tag`、`lane_ctx`、Q46 和 `fake_syndrome` 的真实约束。

少了这一步的后果：每个局部结论都可能“看起来合理”，例如 oracle 能返回 32 字节、蜜罐能写真实变量、MBA 表达式能 SAT，但组合起来缺干净 share 或走错路径，最后只得到 Wrong。

## 10. Material 分片和公开约束

`sub_F020` 是 material 分片加载器。`byte_13e1`、`byte_13ed` 是表锚点，但最终值还要经过 route、bank、rotate、生成式掩码、代码字节派生和比较数据流恢复。

B 侧算法还原时建议先整理这条主线：

```text
干净 padding -> 25+7 字节输入 -> 4 个 u64
  -> 12 轮 ARX material 扩展
  -> oracle encoded head/tag 检查
  -> lane_ctx 滚动上下文
  -> mid_tag 多轮自耦合反馈
  -> Q46 lane-hint 二次 bit 约束
  -> fake_syndrome / SPN 期望状态收尾
```

这条链说明为什么 `material[8:16]` 是建模口：ARX 决定它来自哪个 `flagB` 原像，oracle 和分片检查给公开投影，`lane_ctx` 与 `mid_tag` 绑定 A/oracle/隐藏 lane，Q46 压缩搜索空间，`fake_syndrome` 防止删掉看似噪声的检查。

还原时不要漏掉 `key_schedule` 这一层。它把 material 派生成 `round_keys`、`configs`、`sbox_seeds` 和 `delta`：`sbox_seeds` 对应 oracle seeds；`configs` 选择 S-Box、ShiftRows、MDS 和 nonlinear feedback；`round_keys/delta` 驱动两个 IV 下的 SPN；两个期望状态又被 `soKey` 和 `a_share` 遮罩。这样 material 模型、oracle 检查和双 SPN 期望状态是一组闭合约束，不是三个互不相干的检查。

从 APK/oracle/native 检查中可恢复的公开约束：

```text
material[0:8]        = c1914230477ab658
material[60:64]      = d93d6dee
material[80:96]      = 9f73be24a1dd6c96b90723bba7cdfdc9
oracle_head_enc      = fd521311dd1b1725
oracle_tag           = 72014429f93dd77c
lane_ctx             = 0x129b4a86
mid_tag              = 0x92b28e10
material_lane_hint   = 0x016eff8c39c23
fake_syndrome        = 0xd6
```

隐藏通道：

```text
material[8:16] = 07b943e4d69eb09e
```

WP 给出结果用于说明；实际选手应通过模型求解它。

这些公开约束的含义如下：

| 名词 | IDA/建模时怎么理解 | 漏掉后的结果 |
| --- | --- | --- |
| `lane_ctx` | 32 位滚动上下文。沿数据流看，它不是单独常量比较，而是把隐藏 lane、oracle encoded head、seeds、`soKey`、`a_share` 逐字节混在一起。建模时应把它当隐藏 lane 的一个上下文约束。 | 模型会把 B 侧隐藏 lane 和 A/oracle 解耦，候选会变多或后续 tag 不匹配。 |
| `mid_tag` | 隐藏 lane 的中段非线性 tag。所谓自耦合，是指状态 `a/b/c/d` 每轮更新后继续喂给下一轮，`ch/maj/poly/fbox/MDS/Feistel` 外壳还原后仍保留真实反馈。 | 只做线性或逐字节约束不够，容易得到局部满足但不通过完整 B 校验的候选。 |
| `material_lane_hint` | Q46 真实分支给出的 lane 投影。这里 Q46 指 Quadratic 46：46 条二次布尔关系，不是直接给出 46 个已知 bit；D0Q46 中的 D0 表示 Direct 0，也就是隐藏 lane 没有直接公开位。定位时从 `sub_5998` 走到 `sub_5A38`，不要走 `sub_2ED4` 蜜罐。去混淆后是 46 条 `a ^ (b & c) == bit`。 | 不建这 46 条约束，`material[8:16]` 搜索空间仍太大；建错到蜜罐分支会让 SMT 模型爆炸。 |
| `fake_syndrome` | 8 位 syndrome/check byte。它名字像 fake，但干净路径下仍是实际过滤点，同时与反调试污染和 fake material decoy 有耦合。 | 把它当噪声删掉，可能得到能过 oracle head/mid-tag 的错误 material。 |

少了这一步的后果：只靠 oracle 暴露的 material head 不足以恢复 ARX state；只拿 `byte_13e1`/`byte_13ed` 也不能直接推出隐藏 lane。

## 11. Q46 桥、真实分支和 OLLVM 蜜罐

`sub_5998` 是 Q46 分发桥。它会让静态图靠近大型蜜罐 `sub_2ED4`，但真实 lane-hint 主体在 `sub_5A38`。

`sub_2ED4` 看起来很像真核心：大 switch、TEA-like、MDS/matrix、Q46 shadow、写真实变量名、xref 多。干净路径下它不是主求解目标。

真实 Q46 去混淆后是 46 条二次 bit 约束：

```text
a ^ (b & c) == bit
```

少了这一步的后果：把 `sub_2ED4` 当主线会建模蜜罐；忽略 `sub_5A38` 则 `material[8:16]` 约束不足，候选空间过大。

## 12. MBA 化简和 Bitwuzla 求解

当前 `flag-keygen.py` 只保留 Bitwuzla 后端，只求 `material[8:16]`，不打印最终 flag。运行：

```bash
python3 flag-keygen.py --timeout-ms 600000 --verbose KCTF2026.apk
```

脚本中的模型假设选手已经把 native 中的 MBA 外壳还原为紧凑语义，例如 add/xor/carry、MDS/Feistel 恒等式、ANF/choice/majority 包装、byte projection、Q46 二次 bit 约束。还原后是分钟级求解；不还原 MBA 直接建 raw wrapper/bridge，二十分钟内拿不到第一候选。

少了这一步的后果：直接把 raw MBA/Q46 bridge 全部丢进 SMT 会卡在表达式复杂度上；过度化简把干净 share、poison 或 `fake_syndrome` 当零，也会得到错误模型。

## 13. 恢复 flagB

得到隐藏 lane 后：

```text
material[0:16] = c1914230477ab65807b943e4d69eb09e
```

再反演或建模 12 轮 ARX 原像，并约束干净路径 padding：

```text
input[25:32] = 5a5a5a5a5a5a5a
```

恢复 B lane：

```text
flagB = 7ae31b94d256f80c41b7298e63a5df104bc8723d960fe458ad
```

少了这一步的后果：`flag-keygen.py` 解出的只是隐藏 material lane，不是最终提交输入；如果没有把 key schedule 和双 SPN 期望状态一起核对，可能拿到能过部分 material 约束但不能回到正确 `flagB` 的候选。

## 14. 最终输入

把提交态 A lane 和 B lane 交错：

```text
flag[2*i]   = flagA_submitted[i]
flag[2*i+1] = flagB[i]
```

最终 100 个十六进制字符：

```text
a77a7ae3781bff94c8d2945636f87d0c1b41f5b7bb293f8eaa63b6a5e2dff410db4b00c87072533d3d96e80fb7e4345843ad
```

该值已通过当前发布版校验器和真实设备验证。

## 15. 坑点总表

| 坑点 | 错误做法 | 后果 |
| --- | --- | --- |
| 输入结构 | 把 50 字节当线性 flag 或 `A||B` | 最终交错错误 |
| Java 字符串 | 靠字符串搜 `.kctfguard`/`.text` | 定位不全或漏掉 fallback/profile |
| Java `m` | 只按静态默认值跑 `a()` | profile delta 污染 B padding |
| soKey | 直接用 Java 返回前 16 字节 | A 解码、oracle key、期望值全错 |
| 重打包/patch | 修改 so 后不收敛 | guard/text/oracle key 不匹配 |
| Scheme A | 只当独立 checker 或跳过 | 缺 `a_share`，B 侧 tag/head 错 |
| oracle | 把 output 当明文 material | encoded head 解读错误 |
| hook/dump | Frida/inline hook 关键 libc | 得到稳定但被污染的数据 |
| material 表 | 只读 `byte_13e1`/`byte_13ed` | 只拿到分片入口，不是最终约束 |
| Q46 | 建模 `sub_2ED4` 蜜罐 | 模型爆炸且方向错 |
| key schedule/SPN | 只检查 material 投影，不复核运行时参数和双 SPN 期望状态 | 隐藏 lane 局部可过，但 B 侧完整闭环不过 |
| MBA | 不化简直接 SMT | Bitwuzla 20 分钟内 unknown |
| ARX | 忽略干净路径下的 `0x5a` padding | material 对，flagB 仍错 |
| 假路径 | 把 debug bypass/fake decoy 当真 | 局部看似合理，最终 Wrong |

## 16. 最短正确路线

1. 从 dex 还原 Java 输入格式、`a()` 元数据和字符串解密。
2. 从 native 确认 `collect_java_archive_meta()` 会短暂 patch Java `m`，恢复动态 profile。
3. 从 APK 解析 `.kctfguard`，得到 guard 校验值和 `soKey`。
4. 按 JNI 奇偶拆分恢复 A/B lane 结构。
5. 还原 A 侧提交态到语义态的解码和 repair 链，得到 `a_share=0xd7`。
6. 沿 `sub_10E18` 还原 oracle loader 和 shellcode 输出结构，得到 seeds、encoded head、tag。
7. 从 `sub_F020/sub_F32C` 和比较数据流恢复 material 公开约束。
8. 识别 `sub_5998 -> sub_5A38` 是真实 Q46，排除 `sub_2ED4` 蜜罐。
9. 化简 MBA/Q46 为紧凑位向量模型，用 Bitwuzla 求 `material[8:16]`。
10. 复核 key schedule 派生结果和双 SPN 期望状态，确认 material 候选落在完整 B 侧约束内。
11. 反演或建模 ARX 原像，恢复 `flagB`。
12. 使用提交态 `flagA_submitted` 和 `flagB` 交错，得到最终 100 hex。

如果其中任何一步缺失，题目不会告诉你具体缺哪一步，只会在 Java 层显示 `Wrong`。
