# KCTF2026 当前设计说明

本文是当前发布版的内部设计说明，重点解释题目的混淆层、坑点、可解性边界，以及这些点为什么要放在对应执行阶段。当前发布包中的 `WRITEUP.md` 按本文的依赖链写成选手视角恢复路线。

## 1. 设计目标

这个 Android native 题目保持公开 APK 可解、可离线复现，但避免把解法降级成字符串搜索、单点 patch、一次 hook dump 或直接常量提取。文档只记录设计结构，不记录发布构件指纹、哈希值或当前派生密钥的具体数值。

几条依赖链最关键：Java/archive profile 参与 native 侧 `soKey` 消费和 B 侧 padding；A 侧修复链产出 `a_share` 并反向约束 B；B 侧 12 轮 ARX material 只公开局部投影；oracle 只给 encoded head/tag；隐藏 lane 由 `lane_ctx`、`mid_tag`、Q46、`fake_syndrome` 和双 SPN 期望状态共同收束。

运行时检测、hook 采样和蜜罐路径都不是装饰层。干净路径产出的 share 是算法输入；异常路径不立即失败，而是把误差延迟扩散到 material、oracle tag、期望状态或 ARX 原像里。

最终 Java 层只呈现 `Correct! Flag accepted.` 或 `Wrong`，不会暴露缺失的是哪条依赖。

## 2. 从 Zygote 到 Correct 的执行链

### 2.1 进程启动和 native 早期状态

用户打开 App 后，zygote fork 出应用进程，ART 加载 `MainActivity`。类加载阶段执行 `System.loadLibrary("kctf")`，因此 `libkctf.so` 在用户点击按钮前已经被 `dlopen`。

这个阶段适合放早期环境采样：如果选手从进程启动前后就 attach debugger，错误不会表现为一个清晰的 `debugger detected` 分支，而是通过全局 share 延迟污染 oracle、key schedule 或期望状态。

坑点：从入口按钮开始 trace 可能已经太晚，部分干净路径 share 已经被种下。

### 2.2 Java UI 输入过滤

Java 层只接受 100 个小写十六进制字符，解码为 50 字节后调用 JNI：

```text
nativeProcessInput(byte[] flag)
```

这层故意保持普通：没有网络、没有复杂 UI、没有明显动态加载。它的作用是降低表面复杂度，让选手低估后面的 native 数据流。

坑点：输入不是 `flagA || flagB`。50 字节进入 native 后会按奇偶位拆成两条 lane。

### 2.3 Java APK/archive 元数据

native 会反射调用 Java 短名方法 `a()`。它表面是 APK/so 自检，实际返回 native 后续使用的 32 字节元数据：

```text
meta[0:16]   = masked soKey share
meta[16:20]  = guard crc
meta[20:24]  = guard/text offset
meta[24:28]  = guard/text size
meta[28:32]  = Java archive/profile word
```

Java 侧负责打开当前 APK，定位 `lib/<abi>/libkctf.so`，解析 ELF section，找到 `.kctfguard` 和 `.text`，计算 CRC/profile。把这部分放在 Java 里，是因为 APK 路径、ABI fallback、zip entry 和 dex 侧字符串处理天然属于 Java 视角；它迫使选手同时看 dex 和 native。

混淆点：关键字符串不是明文常量池线索，`lib/`、`libkctf.so`、ABI 名、`.kctfguard`、`.text` 通过短函数和 switch-case 状态机解密。这个平坦化不改变约束，但会降低字符串搜索和 AI 快速总结的稳定性。

### 2.4 native 动态消费 Java metadata

JNI 入口获取 Java metadata 后不会直接相信它。native 会：

```text
解 JNI 方法/签名 token
调用 Java a()
复制 meta[32]
meta[0:16] XOR sokey_share_mask -> soKey
复算 Java profile
复算运行时 .kctfguard/.text 身份
不一致时污染 soKey 或 g_java_archive_profile_delta
```

这里还有当前版本的一个静态/动态分叉：Java 静态字段 `m` 默认是 `0x5EED4A71`，但 native 在 `collect_java_archive_meta()` 里会短暂修改 `m`，调用 Java `a()` 取回 32 字节元数据，然后恢复旧值。

设计意图：

- 静态 Java 视角下，`a()` 看起来可独立复现；
- native 动态视角下，`a()` 的有效 profile 取决于短暂写入的运行时 seed；
- patch 结束后字段恢复，普通动态快照不容易看到差异；
- 这段放在 archive metadata 采集 helper 里，比放在 `fetch_sokey()` 主线更像正常 profile 协商副作用。

最终决定是不继续给这段加大型 vtable、OLLVM 或复杂 MBA。原因是这条坑已经成立：纯静态若忽略 native 写 Java 字段，就会得到错误 profile。继续加大代码面积反而可能让 IDA 里出现更突兀的保护逻辑。

### 2.5 B 侧 padding 被 Java profile 间接控制

`g_java_archive_profile_delta` 不直接报错，而是影响 B 侧 25 字节输入后补的 7 字节 padding。干净路径为：

```text
padding = 0x5a * 7
```

如果 Java profile、运行时 guard 或重打包状态不对，padding 会被污染，后续 ARX material 全部偏掉。

设计意图：把 Java 静态误解延迟传播到 B 侧求解核心。选手如果只看到 `flagB` 后补 `0x5a`，但没有还原 Java/native metadata 的干净路径，会在很后面才得到 Wrong。

### 2.6 JNI 拆分 A/B 和跨 lane 依赖

JNI 将 50 字节按奇偶位拆分：

```text
flagA_submitted[i] = input[2*i]
flagB[i]           = input[2*i+1]
```

A/B 不是完全独立：B 侧 material share 会影响 A 的期望值解密，A 侧通过后产出 `a_share`，再影响 B 的 oracle head/tag 和期望遮罩。

当前提交态 A lane 和语义态 A lane：

```text
flagA_submitted = a77a78ffc894367d1bf5bb3faab6e2f4db0070533de8b73443
flagA_plain     = 0200000001832dbd05c70573e5b979379edec0adde07421337
```

当前 B lane：

```text
flagB = 7ae31b94d256f80c41b7298e63a5df104bc8723d960fe458ad
```

最终输入必须交错，不是拼接：

```text
a77a7ae3781bff94c8d2945636f87d0c1b41f5b7bb293f8eaa63b6a5e2dff410db4b00c87072533d3d96e80fb7e4345843ad
```

### 2.7 Scheme A：语义修复和 share 生成

A 侧不是最终 flag 主体。它做的是 native 语义绑定：解码提交态 A，修复/验证 CFG、S-box、常量和语义状态，然后产出 B 必须使用的 `a_share`。

A 侧算法链路可以概括为：

```text
flagA_submitted
  -> soKey 相关的可逆置换 / XOR / rotate / 加法解码
  -> flagA_plain 字段
  -> 受限跳转语义：B/BL 偏移、TBZ 条件边、ADR 目标和 dispatch 入口
  -> 修 S-box / round constants / step 参数
  -> core_compute 生成语义状态
  -> 期望状态与 soKey、B material_share 组合
  -> diff 聚合，同时折叠出 a_share
```

这里的 CFG 修复不是“任意跳转”或真正改写 `.text`，而是把 A lane 解码出的几个字段解释成受限控制流约束：branch 只能落到预期基本块，TBZ 只能表达预期条件边，ADR 只能指向指定入口，dispatch table 只能进入允许的语义节点。这样 Flag A 不是普通常量比较，而是在验证一组可达性和跳转目标是否同时成立。

这使 A 侧不是一个可独立丢弃的格式检查。它既验证 native 语义字段，也把 B 侧 material 反向接入 A 的期望值，并把 `a_share` 正向送回 B 的 oracle/tag。

当前 A 侧恢复出的基本块/修复字段：

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

A 侧给 B 侧的 share：

```text
a_share = 0xd7
```

坑点：只恢复 B 不够；只把 A 当独立 checker 也不够。A 的输出参与 B 的 oracle/tag，B 的 material 又反过来参与 A 期望遮罩。

### 2.8 Scheme B：ARX material 和公开约束

B 侧输入是 25 字节，后补 7 字节 padding 后成为 32 字节，按四个小端 64 位 word 进入 12 轮 ARX material 扩展。B 侧不会暴露完整 material，只暴露一组可恢复的公开约束：

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

隐藏 lane：

```text
material[8:16] = 07b943e4d69eb09e
```

这个值不作为公开常量给出，预期由选手还原 native MBA/Q46 语义后用 Bitwuzla 建模得到。

这里几个名词需要分清：

| 名词 | 含义 | 为什么重要 |
| --- | --- | --- |
| `lane_ctx` / lane 上下文 | 一个 32 位滚动上下文。它由隐藏 lane `material[8:16]`、公开 material head、oracle encoded head、seeds、`soKey` 和 `a_share` 逐字节反馈得到。 | 它把隐藏 lane 和 oracle/A 侧 share 绑在一起，防止只按 B 侧局部 material 建模。 |
| `mid_tag` / mid-tag 自耦合 | 一个 32 位中段 tag。输入主要是 `material[8:16]` 和已知 material/seeds/soKey，内部经过多轮 `ch/maj/poly/fbox/MDS/Feistel` 风格反馈。这里的“自耦合”指每一轮的状态会回写并影响下一轮，不是独立字节校验。 | 它是隐藏 lane 的非线性过滤器，让 `material[8:16]` 不能靠简单线性方程或低位枚举恢复。 |
| `material_lane_hint` / Q46 lane-hint | Q46 是 Quadratic 46，表示 46 条二次布尔关系，不是直接泄露 46 个隐藏 lane bit。D0Q46 中的 D0 表示 Direct 0，即 `material[8:16]` 没有直接公开位。真实主体在 `sub_5A38`，去混淆后等价于 46 条 `a ^ (b & c) == bit` 约束。 | 它把隐藏 lane 压到适合 Bitwuzla 的 QF_BV 子问题，同时在 IDA 中通过 `sub_5998` 靠近 OLLVM 蜜罐，误导路径选择。 |
| `fake_syndrome` | 一个 8 位 syndrome/check byte。它看起来像假 material 或环境噪声，但干净路径下仍是实际过滤点；污染路径下还会和 fake material decoy 互相放大错误。 | 不能把它当纯蜜罐删掉。过度化简时如果把它视为 0 或忽略，会得到能局部过约束但最终 Wrong 的模型。 |

B 侧算法本身可以按下面的顺序理解：

```text
flagB[25] + profile padding[7]
  -> 4 个 little-endian u64
  -> 12 轮 ARX 扩展
  -> material[0..96)
  -> material 分片检查 / oracle 编码头 / lane 上下文
  -> mid-tag 自耦合反馈
  -> Q46 lane-hint 二次 bit 约束
  -> fake_syndrome 与 SPN 期望状态收尾
```

ARX 扩展负责把 25 字节输入扩散到多个 material lane。公开的 `material[0:8]`、`material[60:64]`、`material[80:96]` 只提供局部投影，不能拼出完整 state。oracle 只验证编码后的 material head 和 tag；`lane_ctx` 把隐藏 lane、oracle 输出、`soKey`、`a_share` 串成滚动上下文；`mid_tag` 用多轮状态反馈压缩隐藏 lane；Q46 进一步给隐藏 lane 加 46 条非线性 bit 约束；`fake_syndrome` 既是过滤点，也和污染路径的 decoy 互相放大错误。

B 侧还有一层运行时参数收口，不能只看 material 投影。`key_schedule(flagB, soKey)` 会把 ARX material 继续派生成：

```text
round_keys[16]
configs[16] = sbox_selector / shift_pattern / mix_matrix_idx / nonlinear_mode
sbox_seeds[4]
delta
```

其中 `sbox_seeds` 要和 oracle seeds 对齐；`round_keys/configs/delta` 驱动两个 IV 下的 SPN；期望状态再被 `soKey` 和 `a_share` 做交叉遮罩。也就是说，`material[8:16]` 模型只恢复隐藏 lane，双 SPN 期望状态才把 material 候选收束到能反推 `flagB` 的唯一原像。

设计意图：早期版本过于容易通过公开 material 窗口代数反推。当前版本把主要求解口收紧到 `material[8:16]`，但仍通过 key schedule、oracle 投影、mid-tag/Q46 和双 SPN 期望状态保证完整 B 侧约束闭合。解题必须先还原算法投影和 MBA 语义，再建模隐藏 lane，最后反推 ARX 原像得到 `flagB`。

### 2.9 Oracle loader 和 shellcode

Oracle 路径是真路径，不是装饰。当前实现不在导入表直接暴露 `mmap`、`munmap`、`mprotect`，而是通过解析器/dlsym 和 AArch64 SVC 后备路径建立映射，再分阶段 XOR 解密 payload、执行、清理。

Oracle 输出格式：

```text
seeds[16] || encoded_material_head[8] || tag[8]
```

`.L_oracle_data` 不是 32 字节明文数组。当前后备存储区为 48 字节：32 字节置换载荷加 16 字节生成式解码表。shellcode 使用如下形式恢复输出字节：

```text
pos = (i * 5 + 11) & 31
```

再叠加查表、rotate 和索引相关掩码。

设计意图：oracle 数据仍然静态可恢复，但不能靠字符串/数组搜索直接拿。动态 dump 也不能盲信，因为环境检测会把错误折进输出。

### 2.10 反调试/反 hook 作为数据误差

本题避免把检测写成明显的：

```text
if bad: return false
```

而是让干净/污染 share 影响：

```text
oracle key
oracle material 解码
key schedule delta
Java profile padding
material tag
fake_syndrome
期望状态
```

Oracle shellcode 和 C 层 preflight 会检查：

```text
TracerPid
/proc/self/maps 中 frida/gum/xposed/gadget 痕迹
HWCAP/运行环境能力
关键 libc 函数入口形态
mmap 前几条指令是否出现 B/BL 或 LDR literal + BR/BLR 跳板
```

命中后不要求立刻崩溃，而是返回格式正确但内容错误的 oracle/material。选手 hook 到的数据可能稳定、可解析、可建模，但最终仍然 Wrong。

这类耦合不只发生在 oracle payload。当前设计把运行时状态、数据派生、MBA 包装和蜜罐诱饵分散接进多条真实算法链：

| 来源 | 接入位置 | 干净路径语义 | 错误处理后的表现 |
| --- | --- | --- | --- |
| Java/native archive profile | `soKey` 消费、B 侧 padding、运行时 guard 复核 | 产出稳定 metadata/profile share | 静态 Java profile 或重打包状态错误时，B 侧 ARX material 延迟偏移 |
| native 早期采样和 libc 入口检查 | key schedule、oracle 解码、期望遮罩、`fake_syndrome` | 产出确定的干净/污染 share，不作为单独返回值 | patch 检测或 inline hook 可能得到格式正常但内容错误的数据 |
| oracle loader 和 payload | seeds、encoded material head、oracle tag，以及后续 `lane_ctx`/`mid_tag` 检查 | 恢复可公开逆出的 oracle 约束 | dump 到污染输出会让后续 material/tag/SPN 全部像算法错误 |
| MBA 包装和非线性投影 | `lane_ctx`、`mid_tag`、`material_lane_hint`、`fake_syndrome`、material projection | 一部分是恒等包装，一部分是真实非线性约束 | 全删会漏约束，原样全丢 SMT 会显著拖慢 |
| OLLVM/bait/fake 路径 | Q46 bridge 附近、oracle 失败边、诱饵缓存、真实变量名写入 | 干净路径下只提供可判别诱饵或被掩掉的副作用 | 当真路径建模会进入蜜罐，模型膨胀且方向错误 |

因此这里的正确分析顺序不是“先删保护，再看算法”，而是先证明干净路径，再判断哪些数据流是恒等包装、哪些是必须保留的真实约束。运行时采样贡献的干净 share、mid-tag 的状态反馈、Q46 的二次 bit 关系、`fake_syndrome` 的字节折叠都不能因为看起来像保护或噪声就删除。

### 2.11 Q46、MBA 和必须建模的隐藏 lane

`material[8:16]` 的约束来自多个层次：mid-tag 自耦合、lane 上下文、`fake_syndrome`、Q46 lane-hint，以及 SPN/ARX 原像约束。关键 lane-hint 通过 Q46 桥到真实主体，恢复后是 46 条二次 bit 约束：

```text
a ^ (b & c) == bit
```

外层混入：

```text
MDS/Feistel 恒等式
ANF/choice/majority 包装
add/xor/carry MBA
trunc/mask/byte projection
地址诱导和 bait bus 噪声
```

设计意图：

- 不让 `material[8:16]` 变成数组提取；
- 不让求解退化成低位枚举；
- 还原 MBA 后，Bitwuzla 可以在数分钟级求解；
- 未还原 MBA 直接喂 SMT，应显著慢于官方路线。

### 2.12 OLLVM 蜜罐和假目标

当前蜜罐核心是大型 OLLVM 风格 lattice 函数。它包含 switch 状态机、TEA-like、MDS/matrix、Q46 shadow、NTT-like、多轮伪状态更新，并写入看起来真实的全局变量名：

```text
round_constants
xtea_delta
step2_amount
step3_param
sbox_shipped
dispatch_table
```

但干净路径不应把它当主求解目标。它的价值是让 IDA/Ghidra/AI 看到一个体积大、xref 多、变量名真实、控制流复杂的候选核心。

设计意图：反 AI 的重点不是“所有代码都复杂”，而是让 AI 的局部正确总结组合后仍然错。看到 TEA/Q46/MBA/NTT 形状并不等于路径真实，必须先证明可达性。

## 3. 当前 IDA 复核点

当前发布版在 IDA 中应呈现为以下结构：

```text
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
oracle_code                    = 0x1470..0x1930
```

当前复核结果：

- 导入表没有直接 `mmap`、`munmap`、`mprotect`；
- 明文搜索 `frida`、`gum`、`TracerPid`、`/proc`、`material`、`oracle`、`flag`、`deriveNativeKey`、`()[B` 不应给出直接路线；
- 连续字节搜索最终 flag、`soKey`、guard CRC、`material[8:16]`、oracle head/tag 不应命中；
- `sub_10E18` 在当前 IDA MCP 中反编译失败，反汇编能看到 dlsym/SVC、载荷范围、间接跳转和蜜罐边；
- `sub_5998` 会在 `sub_2ED4` 蜜罐和 `sub_5A38` 真实 Q46 分支之间做间接分发。

发布包已清理 AGP VCS 元数据、AGP 应用元数据和 `DebugProbesKt.bin`。这只清理打包噪声，不改变 APK 内 native 库、guard、oracle 和求解约束。

## 4. 必须还原的依赖和缺失后果

| 必须还原的点 | 为什么需要 | 少了会怎样 |
| --- | --- | --- |
| 100 hex 到 50 字节，再奇偶拆 A/B | 最终输入是交错结构 | 把 A/B 拼接会得到 Wrong |
| Java 字符串解密和 `a()` 元数据 | soKey/profile 来自 APK archive | 找不到 `.kctfguard`/`.text` 或用错 Java 返回值 |
| native 动态 patch Java `m` | profile 的干净路径依赖运行时 seed | 静态 `m=0x5EED4A71` 会给出错误 padding/profile |
| `.kctfguard` / 运行时 guard / `soKey` | A 解码、oracle key、B 侧期望值都依赖它 | A/B 都像算法错，实际是 key 污染 |
| Java profile -> B padding | ARX 原像末尾 7 字节只有干净路径是 `0x5a` | 反演 flagB 时 material 全偏 |
| Scheme A 修复链 | 产生 `a_share`，也验证 native 语义 | oracle head/tag 缺 `a_share`，期望遮罩也会错 |
| oracle loader 解密 | seeds/head/tag 不以明文数组出现 | 只靠 native 表无法获得完整公开约束 |
| 反调试 share | 检测结果参与算法，不是可删分支 | hook/dump 出稳定但错误的数据 |
| material 分片和生成表 | `byte_13e1`/`byte_13ed` 只是入口 | 只拿表不能推出隐藏 lane |
| native 常量分散和代码字节派生 | material 期望值、lane hint、oracle mask 等不是完整直观数组 | 只做连续数组提取会漏掉生成式修正和局部 mask |
| Q46 真实分支 `sub_5A38` | 约束 `material[8:16]` | 忽略后候选空间过大或模型不收敛 |
| B 侧运行时参数和双 SPN 期望状态 | material 候选还要派生 `round_keys`、`configs`、`sbox_seeds`、`delta` 并通过两个期望状态 | 只满足公开 material 投影，仍可能不是有效 `flagB` 原像 |
| OLLVM 蜜罐可达性判断 | `sub_2ED4` 看起来像真核心 | 建模蜜罐会爆炸且方向错误 |
| MBA 化简 | raw 表达式对 SMT 成本高 | Bitwuzla 20 分钟内拿不到第一候选 |
| ARX 原像和 `0x5a` padding | 隐藏 material 不是最终 flagB | 只求 material 仍不能提交 |
| 最终 A/B 交错 | Java 收的是 50 字节交错输入 | lane 都对但最终字符串错 |

## 5. 可解性边界

发布版辅助脚本 `flag-keygen.py` 刻意不是完整私有 keygen。它只做一件事：使用选手可从 APK 逆到的公开约束，用 Bitwuzla 求解 `material[8:16]`。

脚本数据源包括：

- APK 内 `libkctf.so` 的 `.kctfguard` 和 `soKey`；
- Java/native 可恢复的 archive/profile 干净路径；
- oracle loader 可恢复的 seeds、encoded material head 和 tag；
- native material 检查恢复出的 `lane_ctx`、`mid_tag`、`fake_syndrome`、`material_lane_hint`；
- 去混淆后的 46 条 Q46 lane 投影。

脚本不应该使用选手无法得到的源码私有状态，也不应该直接给出完整 flag。WP 中给出最终 flag 是题解说明，求解辅助脚本只验证 material 通道。

## 6. 求解成本边界

辅助脚本只求 `material[8:16]`，不生成完整 flag。预期逆向路线是先从 native 中还原 MBA/Q46 语义，再把紧凑后的隐藏 lane 约束交给 Bitwuzla。

当前发布版的目标状态是：还原 MBA 后可在分钟级恢复隐藏 lane；不还原 MBA、直接把 raw wrapper/bridge 表达式交给 SMT 时，二十分钟内拿不到第一候选。这个时间只作为复杂度边界，不作为题目条件。
