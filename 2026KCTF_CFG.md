# 2026 KCTF 项目控制流图（方案 B + AI 蜜罐）

## ==顶层调用流==

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Android Application                               │
│                                                                          │
│  MainActivity.onClick()                                                  │
│       │                                                                  │
│       ▼                                                                  │
│  JNI: nativeProcessInput(flag_bytes[25])  ← 只传 flag                    │
│       │                                                                  │
│       │  (native 内部通过 JNI 回调 deriveNativeKey() 获取 soKey[16])      │
│       │                                                                  │
└───────┼──────────────────────────────────────────────────────────────────┘
        │
        ▼  ═══ 进入 Native 层 (libchallenge.so) ═══
        │
┌───────┼──────────────────────────────────────────────────────────────────┐
│       ▼                                                                  │
│  processInput()  ← JNI 入口                                             │
│       │                                                                  │
│       ├──→ fetch_sokey(env, obj, soKey)  ← JNI 回调 Java 层              │
│       │                                                                  │
│       ├──→ key_schedule(flag, soKey, &params)                            │
│       │         │                                                        │
│       │         ├──→ expand_key_material(flag, material, 96)             │
│       │         │         └──→ [蜜罐 B: adapt_cache_strategy()]          │
│       │         ├──→ get_ipc_material(ipc)                               │
│       │         └──→ 派生 round_keys / configs / sbox_seeds / delta      │
│       │                                                                  │
│       ├──→ generate_sbox(seed, sbox) × 4                                 │
│       │         └──→ [蜜罐 C: adjust_logging()]                          │
│       │                                                                  │
│       ├──→ spn_encrypt(state, &params)  ← 16 轮 SPN                     │
│       │         └──→ spn_round() × 16                                    │
│       │               ├──→ [蜜罐 A: 检查 g_render_mode]                  │
│       │               ├──→ apply_sbox()                                  │
│       │               ├──→ shift_rows()                                  │
│       │               ├──→ mix_columns_mds()                             │
│       │               │         └──→ gf_mul() × 64/轮                    │
│       │               ├──→ nonlinear_feedback()                          │
│       │               │         ├──→ [蜜罐 D: calibrate_frame_budget()]  │
│       │               │         └──→ gf_pow() × 16/轮                    │
│       │               └──→ add_round_key_full()                          │
│       │                                                                  │
│       ├──→ 解密目标状态: expected = ENC_EXPECTED_STATE ^ soKey           │
│       │                                                                  │
│       └──→ 常量时间比较(final_state, expected, 16) → 返回结果            │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## ==初始化阶段（进程加载时）==

```
linker 加载 libchallenge.so
       │
       ▼
__attribute__((constructor(101)))
early_init()                          [init.c]
       │
       ├── open("/proc/self/status")
       ├── parse_tracer_pid()
       └── 写入 g_render_mode          ← 检测点 A
```

**early_init()**
- 作用：进程启动时检测 TracerPid，写入 g_render_mode
- 编译单元：init.c
- 内联：否（constructor 不可内联）
- 蜜罐变量：g_render_mode（伪装名：渲染模式）

---

## ==Java 层详细流==

```
MainActivity.onClick(View v)
       │
       ▼
String input = editText.getText()
byte[] flag = Base64.decode(input)     // 25 字节
       │
       ▼
int result = nativeProcessInput(flag)  // JNI 调用，只传 flag
       │                               // native 内部回调 deriveNativeKey() 拿 soKey
       ▼
if (result == 1) showSuccess() else showFail()
```

### deriveNativeKey() — Java 层 soKey 派生（被 native 回调）

```
deriveNativeKey()                      [MainActivity.java]
       │                               (由 native 层 JNI CallObjectMethod 触发)
       │
       ├── 1. 解析 /proc/self/maps
       │       └── 找 "libchallenge.so" + " r-xp " 行
       │       └── 提取 execStart, execEnd
       │
       ├── 2. 读取 /proc/self/mem
       │       └── seek(execStart), readFully(text[])
       │
       ├── 3. CRC32(text[])
       │       └── crcVal (32-bit)
       │
       └── 4. LCG 扩展为 16 字节
               └── 4 轮: m = (crcVal ^ EXPAND[i]) * MUL + ADD
               └── 每轮产出 4 字节 → key[16]
```

- 作用：从 .text 段内容派生 soKey，检测运行时 hook/patch
- 调用方式：native 层通过 JNI `CallObjectMethod` 回调（非 Java 层主动调用）
- 关键：Frida hook 会改变 .text → CRC 变化 → soKey 错误 → 全链路失败
- 安全：hook nativeProcessInput 的参数只能看到 flag，看不到 soKey 传递

---

## ==Native 入口：processInput()==

```
JNIEXPORT jint JNICALL
Java_com_kctf_challenge_MainActivity_nativeProcessInput(
    JNIEnv *env, jobject obj, jbyteArray jflag)
       │
       ├── 1. 提取 flag[25] 从 JNI 数组
       │
       ├── 2. fetch_sokey(env, obj, soKey)  ← JNI 回调 Java deriveNativeKey()
       │
       ├── 3. key_schedule(flag, soKey, &params)
       │
       ├── 4. for (i=0; i<4; i++) generate_sbox(params.sbox_seeds[i], sboxes[i])
       │
       ├── 5. spn_encrypt(state, &params, sboxes)
       │
       ├── 6. 解密目标状态: expected[i] = ENC_EXPECTED_STATE[i] ^ soKey[i]
       │
       └── 7. 常量时间比较 final_state == expected → return 1 或 0
```

- 作用：JNI 入口，协调整个验证流程
- 编译单元：jni_entry.c
- 内联：否（JNI 导出函数）
- 参数：只接收 flag[25]，soKey 通过内部 JNI 回调获取
- 蜜罐命名：`nativeProcessInput`（正常命名，不伪装）

### fetch_sokey() — Native 层 JNI 回调

```
fetch_sokey(JNIEnv *env, jobject obj, uint8_t out[16])   [jni_entry.c]
       │
       ├── GetObjectClass(env, obj) → clazz
       ├── GetMethodID(env, clazz, "deriveNativeKey", "()[B") → mid
       ├── CallObjectMethod(env, obj, mid) → jbyteArray
       └── GetByteArrayRegion → out[16]
```

- 作用：通过 JNI 回调 Java 层的 deriveNativeKey() 获取 soKey
- 编译单元：jni_entry.c（static 函数）
- 内联：**是**（static，仅 processInput 调用一次）
- 安全意义：soKey 不出现在 nativeProcessInput 的参数列表中

---

## ==key_schedule() 详细流==

```
key_schedule(flag[25], soKey[16], *params)      [key_expand.c]
       │
       ├── expand_key_material(flag, material, 96)
       │       │
       │       ├── [蜜罐 B] adapt_cache_strategy()
       │       │       ├── clock_gettime(t1)
       │       │       ├── 计算循环 (1000 次)
       │       │       ├── clock_gettime(t2)
       │       │       └── g_cache_policy = (delta > 50ms) ? 0x07 : 0x03
       │       │
       │       ├── 填充: flag→s[4], padding 0x5A
       │       │
       │       ├── ARX 混合循环（无分支蜜罐）:
       │       │   penalty = (g_cache_policy != 0x03) * 4  ← CSEL，无跳转
       │       │   rounds = 12 - penalty  // 正常=12，异常=8
       │       │   for r in 0..rounds:
       │       │       s[0] = (ror64(s[0],8) + s[1]) ^ r
       │       │       s[1] = rol64(s[1],3) ^ s[0]
       │       │       s[2] = (ror64(s[2],8) + s[3]) ^ (r+4)
       │       │       s[3] = rol64(s[3],3) ^ s[2]
       │       │       s[0] ^= s[3]
       │       │       s[2] ^= s[1]
       │       │
       │       └── Squeeze 输出 96 字节:
       │           while pos < 96:
       │               memcpy(out+pos, s, 32)
       │               s[0]+=s[2]; s[1]^=s[3]
       │               s[2]=rol64(s[2],17); s[3]=ror64(s[3],11)
       │
       ├── soKey 混入:
       │       material[96+i] = material[i] ^ soKey[i]  (i=0..15)
       │
       ├── IPC 混入:
       │       get_ipc_material(ipc[16])
       │       material[112+i] = material[32+i] ^ ipc[i]  (i=0..15)
       │
       ├── 派生 round_keys[16]:
       │       params->round_keys[i] = *(uint32_t*)(material + i*4)
       │
       ├── 派生 configs[16]:
       │       每字节 material[64+i] 拆为 4 个 2-bit 字段
       │       sbox_selector / shift_pattern / mix_matrix_idx / nonlinear_mode
       │
       ├── 派生 sbox_seeds[4]:
       │       params->sbox_seeds[i] = *(uint32_t*)(material + 80 + i*4)
       │
       ├── 派生 delta:
       │       params->delta = *(uint32_t*)(material + 96)
       │
       └── soKey 双向验证（无分支）:
               check = round_keys[15] ^ *(uint32_t*)&soKey[12]
               diff = check ^ EXPECTED_SOKEY_CHECK
               poison = ((diff | (~diff+1)) >> 31) * 0xDEADBEEF
               params->delta ^= poison
               // 正确→poison=0; 错误→delta被0xDEADBEEF污染
```

### expand_key_material()
- 作用：将 25 字节 flag 通过 ARX 扩展为 96 字节密钥材料
- 编译单元：key_expand.c
- 内联：否（被 key_schedule 调用，体积大）
- 蜜罐命名：`chacha20_quarter_round`（伪装为 ChaCha20）
- 蜜罐机制：g_cache_policy 控制 ARX 轮数（正常 12，异常 8）

### adapt_cache_strategy()
- 作用：时间差检测（检测点 B）
- 编译单元：key_expand.c（与 expand_key_material 同文件）
- 内联：**是**（static，编译器自动内联到 expand_key_material）
- 蜜罐命名：伪装为"缓存策略自适应"

### get_ipc_material()
- 作用：fork 子进程 ptrace 读取父进程 .text，HMAC 校验
- 编译单元：ipc_verify.c
- 内联：否（含 fork/ptrace 系统调用，体积大）
- 蜜罐命名：无特殊伪装（可选层，可能被 fallback 替代）

---

## ==generate_sbox() 详细流==

```
generate_sbox(seed, sbox[256])                  [sbox_gen.c]
       │
       ├── [蜜罐 C] if (!g_logging_checked):
       │       ├── adjust_logging()  ← 仅首次调用执行
       │       │       ├── fopen("/proc/self/maps")
       │       │       ├── 逐行扫描 "frida" / "xposed" / "substrate" / "gadget"
       │       │       └── g_log_verbosity = suspicious ? 0x00 : 0x02
       │       └── g_logging_checked = 1
       │
       ├── 初始化恒等置换: sbox[i] = i
       │
       ├── 确定 shuffle 范围:
       │   limit = (g_log_verbosity == 0x02) ? 255 : 128  ← 蜜罐分支
       │
       └── Fisher-Yates shuffle (xorshift32 驱动):
           for i = limit downto 1:
               xs ^= xs<<13; xs ^= xs>>17; xs ^= xs<<5
               j = xs % (i+1)
               swap(sbox[i], sbox[j])
```

- 作用：从 seed 生成 256 字节双射置换表
- 编译单元：sbox_gen.c
- 内联：否（被调用 4 次，首次调用执行检测并缓存结果）
- 蜜罐命名：`aes_sbox_init`（伪装为 AES S-Box 初始化）
- 蜜罐机制：g_log_verbosity 控制 shuffle 范围（正常 255，异常 128）

### adjust_logging()
- 作用：/proc/self/maps 扫描（检测点 C）
- 编译单元：sbox_gen.c（与 generate_sbox 同文件）
- 内联：**是**（static，编译器自动内联）
- 蜜罐命名：伪装为"日志级别调整"

---

## ==spn_encrypt() 详细流==

```
spn_encrypt(state[16], *params, sboxes[4][256])  [spn_core.c]
       │
       └── for round = 0..15:
               │
               ├── 轮密钥计算:
               │   dynamic_key = params->round_keys[round]
               │   if (round >= 12):
               │       dynamic_key ^= *(uint32_t*)&state[0]  ← 后4轮反馈!
               │
               └── spn_round(state, &params->configs[round],
                             dynamic_key, params->delta, round, sboxes)
```

- 作用：16 轮 SPN 网络主循环，含轮密钥动态反馈
- 编译单元：spn_core.c
- 内联：否（顶层循环驱动）
- **高耦合**：后 4 轮 round_keys[N] 与当前 state[0:4] XOR，与动态 S-Box 对齐

---

## ==spn_round() 详细流==

```
spn_round(state[16], *cfg, round_key, delta, round, sboxes)  [spn_round.c]
       │
       ├── [蜜罐 A] 检查 g_render_mode (显式分支，选手突破口):
       │   if (__builtin_expect(g_render_mode, 0)):
       │       ├── AES_SBOX 替代 (标准 AES S-Box)
       │       ├── shift_rows_standard()
       │       ├── XOR round_key (简化版)
       │       └── return  ← 蜜罐提前返回
       │
       ├── S-Box 动态选择:
       │   if (round < 12):
       │       sbox_sel = cfg->sbox_selector                    ← 静态
       │   else:
       │       sbox_sel = (cfg->sbox_selector ^ state[0]) & 0x03  ← 动态!
       │
       ├── apply_sbox(state, sbox_sel, sboxes)
       │       └── state[i] = sboxes[sbox_sel][state[i]]  (i=0..15)
       │
       ├── shift_rows(state, SHIFTS[cfg->shift_pattern])
       │       └── 按模式循环左移各行
       │
       ├── mix_columns_mds(state, MDS[cfg->mix_matrix_idx])
       │       └── 4 列 × 4×4 矩阵乘法 (GF(2^8))
       │           └── gf_mul() × 16/列 × 4 列 = 64 次
       │
       ├── nonlinear_feedback(state, cfg->nonlinear_mode, delta, round)
       │       │
       │       ├── [蜜罐 D] if (round==0): calibrate_frame_budget()
       │       │       ├── 扫描 .text 前 4KB 检查 BRK 指令
       │       │       └── g_frame_budget_ns = brk ? 8.3ms : 16.6ms
       │       │
       │       ├── power = NL_POWER[mode & 0x03]  // {3,5,7,11}
       │       ├── round_const = (delta >> (round%4 * 8)) & 0xFF
       │       │
       │       ├── budget_flag = (g_frame_budget_ns < 16000000)  ← 无分支!
       │       └── for i in 0..15:
       │               correct = gf_pow(state[i]^round_const^round, power)
       │               simple  = state[i] ^ round_const ^ round ^ power
       │               poison  = budget_flag * (correct ^ simple)
       │               state[i] = correct ^ poison
       │
       └── add_round_key_full(state, round_key)
               └── state[i] ^= ((uint8_t*)&round_key)[i % 4]  (i=0..15)
```

### spn_round()
- 作用：单轮 SPN 变换（SubBytes + ShiftRows + MixColumns + NonlinearFeedback + AddRoundKey）
- 编译单元：spn_round.c
- 内联：否（体积大，含蜜罐分支，被调用 16 次）
- 蜜罐命名：无特殊伪装（函数名正常）
- 蜜罐机制：g_render_mode 控制是否走 AES 快速路径（显式分支，选手突破口）
- **高耦合**：后 4 轮 S-Box 选择依赖 state[0] 低 2 bit

### apply_sbox()
- 作用：16 字节逐字节查表替换
- 编译单元：spn_round.c
- 内联：**是**（极简逻辑，热路径，必须内联）
- 实现：`for(i=0;i<16;i++) state[i] = sboxes[sel][state[i]];`

### shift_rows()
- 作用：按指定模式对 4×4 状态矩阵行循环移位
- 编译单元：spn_round.c
- 内联：**是**（固定大小循环，热路径）

### mix_columns_mds()
- 作用：4 列各自乘以选定的 4×4 MDS 矩阵（GF(2^8)）
- 编译单元：spn_round.c
- 内联：否（含嵌套循环 + gf_mul 调用，体积较大）

### gf_mul()
- 作用：GF(2^8) 有限域乘法（不可约多项式 0x11B）
- 编译单元：gf_math.c
- 内联：**是**（被 mix_columns_mds 和 gf_pow 高频调用，必须内联）
- 蜜罐命名：无（基础数学运算）

### gf_pow()
- 作用：GF(2^8) 幂运算（快速幂）
- 编译单元：gf_math.c
- 内联：**是**（被 nonlinear_feedback 每轮调用 16 次）

### nonlinear_feedback()
- 作用：非线性反馈层，对 state 每字节做 GF(2^8) 幂次变换
- 编译单元：nonlinear.c
- 内联：否（含蜜罐检测 calibrate_frame_budget）
- 蜜罐命名：`sm4_L_transform`（伪装为 SM4 线性变换）
- 蜜罐机制：g_frame_budget_ns 通过**无分支乘法折叠**污染结果（无 if 跳转）

### calibrate_frame_budget()
- 作用：扫描 .text 检测 BRK 断点指令（检测点 D）
- 编译单元：nonlinear.c（与 nonlinear_feedback 同文件）
- 内联：**是**（static，仅首轮调用一次）
- 蜜罐命名：伪装为"帧预算校准"

### add_round_key_full()
- 作用：将 32-bit round_key 扩展 XOR 到 16 字节 state
- 编译单元：spn_round.c
- 内联：**是**（单行循环，极简）

---

## ==辅助函数==

### 最终验证
- 作用：解密 ENC_EXPECTED_STATE（用 soKey XOR），与 final_state 常量时间比较
- 编译单元：jni_entry.c（内联在 processInput 中）
- 内联：**是**（防止独立 memcmp 符号被 hook）
- 注意：ENC_EXPECTED_STATE 在二进制中看起来是随机数据，选手需先正确派生 soKey 才能得到目标值

### parse_tracer_pid()
- 作用：从 /proc/self/status 文本中提取 TracerPid 字段值
- 编译单元：init.c
- 内联：**是**（static，仅 early_init 调用）

### find_mapping()
- 作用：从 /proc/self/maps 解析指定库的加载基址
- 编译单元：utils.c
- 内联：否（含文件 I/O）

### get_func()
- 作用：运行时动态解析系统函数地址（反 IDA 交叉引用）
- 编译单元：resolver.c
- 内联：否（需要保持间接调用特征以对抗静态分析）
- 蜜罐命名：无（本身就是混淆手段）

### get_string() — 多密钥字符串解密
- 作用：运行时解密字符串，每条字符串使用不同来源的 XOR 密钥
- 编译单元：strings.c
- 内联：否（被多处调用）
- 蜜罐联动：解密出的字符串包含 "AES-256-CBC" 等诱导文本
- 多密钥机制：6 种 key_source（SBOX / RCON / DELTA / HMAC / CRC / COMPOUND）
- 安全性：找到一条字符串的密钥无法解密其他字符串

### derive_str_key()
- 作用：根据 key_source 和 key_param 派生单条字符串的解密密钥
- 编译单元：strings.c
- 内联：**是**（static，融入 get_string 避免独立符号暴露密钥派生逻辑）
- 6 种来源：g_aes_sbox[n] / honey_rcon[n] / delta 字节 / ipc 字节 / soKey 字节 / 三源混合

---

## ==蜜罐函数（独立编译单元）==

这些函数是"真实算法的正确实现"，作为蜜罐路径的执行体。
它们被蜜罐分支调用，或作为 AI 分析的诱饵存在。

### honey_tea_path()
- 作用：标准 TEA 加密（但 delta 差 1）
- 编译单元：tea_impl.c
- 内联：否（需要保持完整函数签名供 AI 识别）
- 蜜罐命名：`tea_encrypt_block`
- 被调用位置：蜜罐路径中作为"备用加密"

### honey_aes_path()
- 作用：标准 AES-128 加密（但 S-Box 是恒等映射）
- 编译单元：aes_impl.c
- 内联：否（需要保持 10 轮结构供 AI 识别）
- 蜜罐命名：`aes_128_encrypt`
- 被调用位置：蜜罐 A 分支内部

### shift_rows_standard()
- 作用：标准 AES ShiftRows（固定 {0,1,2,3} 移位）
- 编译单元：aes_impl.c
- 内联：**是**（仅在 honey_aes_path 内使用）

### mix_columns_standard()
- 作用：标准 AES MixColumns（固定矩阵 {2,3,1,1}）
- 编译单元：aes_impl.c
- 内联：否（与 mix_columns_mds 结构相似，保持独立以防编译器合并）

---

## ==编译单元总览==

```
libchallenge.so
├── jni_entry.c          processInput(), fetch_sokey() [JNI 导出 + JNI 回调]
├── key_expand.c         key_schedule(), expand_key_material(), adapt_cache_strategy()
│                        蜜罐变量: g_cache_policy (static)
├── ipc_verify.c         get_ipc_material()
├── sbox_gen.c           generate_sbox(), adjust_logging()
│                        蜜罐变量: g_log_verbosity (static)
├── spn_core.c           spn_encrypt()
├── spn_round.c          spn_round(), apply_sbox(), shift_rows(), add_round_key_full()
│                        蜜罐变量: 读取 g_render_mode (extern)
├── nonlinear.c          nonlinear_feedback(), calibrate_frame_budget()
│                        蜜罐变量: g_frame_budget_ns (static)
├── gf_math.c            gf_mul(), gf_pow()  [纯数学，无蜜罐]
├── init.c               early_init() [constructor], parse_tracer_pid()
│                        蜜罐变量: g_render_mode (定义处)
├── sha256.c             sha256()  [仅用于 IPC HMAC，非最终验证]
├── resolver.c           get_func()  [动态符号解析]
├── strings.c            get_string()  [字符串解密]
├── utils.c              find_mapping()
├── tea_impl.c           honey_tea_path()  [蜜罐: TEA 实现]
└── aes_impl.c           honey_aes_path(), shift_rows_standard(), mix_columns_standard()
                         [蜜罐: AES 实现]
```

**编译隔离要点**：
- 每个含蜜罐变量的 .c 文件用 `static` 限定变量作用域
- g_render_mode 例外：定义在 init.c，spn_round.c 通过 `extern` 引用（因为 constructor 和使用点必须跨文件）
- `-fno-lto` 防止链接时优化合并相似函数
- `-fvisibility=hidden` 防止蜜罐变量出现在动态符号表

---

## ==内联决策总表==

| 函数 | 内联 | 理由 |
|------|------|------|
| processInput | 否 | JNI 导出，不可内联 |
| fetch_sokey | **是** | static，仅 processInput 调用一次，JNI 回调获取 soKey |
| key_schedule | 否 | 顶层协调函数，体积大 |
| expand_key_material | 否 | 含循环 + squeeze，体积大 |
| adapt_cache_strategy | **是** | static，检测逻辑应融入 expand_key_material 避免独立符号 |
| get_ipc_material | 否 | 含 fork/ptrace 系统调用 |
| generate_sbox | 否 | 被调用 4 次，含蜜罐检测 |
| adjust_logging | **是** | static，融入 generate_sbox 避免独立符号 |
| spn_encrypt | 否 | 顶层循环 |
| spn_round | 否 | 体积大，含蜜罐分支 |
| apply_sbox | **是** | 16 字节查表，极简热路径 |
| shift_rows | **是** | 固定循环，热路径 |
| mix_columns_mds | 否 | 嵌套循环 + 64 次 gf_mul |
| gf_mul | **是** | 被高频调用（每轮 64+16×8=192 次） |
| gf_pow | **是** | 被每轮调用 16 次，快速幂循环 |
| nonlinear_feedback | 否 | 含蜜罐检测 + 分支 |
| calibrate_frame_budget | **是** | static，仅首轮调用，融入 nonlinear_feedback |
| add_round_key_full | **是** | 单行循环 |
| parse_tracer_pid | **是** | static，仅 early_init 调用 |
| early_init | 否 | constructor 属性，不可内联 |
| sha256 | 否 | 仅用于 IPC HMAC 校验，非最终验证 |
| find_mapping | 否 | 含文件 I/O |
| get_func | 否 | 需保持间接调用特征 |
| get_string | 否 | 被多处调用 |
| derive_str_key | **是** | static，融入 get_string 避免暴露密钥派生逻辑 |
| honey_tea_path | 否 | 需保持完整函数供 AI 识别 |
| honey_aes_path | 否 | 需保持 10 轮结构供 AI 识别 |
| shift_rows_standard | **是** | 仅在 honey_aes_path 内使用 |
| mix_columns_standard | 否 | 防止编译器与 mix_columns_mds 合并 |

**内联原则**：
1. 热路径上的小函数必须内联（apply_sbox, gf_mul, gf_pow, shift_rows, add_round_key_full）
2. 蜜罐检测函数必须内联到宿主函数（adapt_cache_strategy, adjust_logging, calibrate_frame_budget, parse_tracer_pid）— 避免产生独立符号被 xref 定位
3. 密钥派生逻辑必须内联（derive_str_key）— 防止逆向者通过单一函数符号定位所有字符串解密密钥来源
4. 蜜罐执行体不内联（honey_tea_path, honey_aes_path）— 需要保持完整函数签名和结构供 AI 模式匹配
5. 含系统调用/文件 I/O 的函数不内联（get_ipc_material, find_mapping）

---

## ==数据流依赖图（高耦合版）==

```
flag[25] ──────────────────────────────────────────────────────────────┐
    │                                                                  │
    ▼                                                                  │
expand_key_material(flag) → material[128]                              │
    │                           │                                      │
    │    soKey[16] ─────────────┤ (XOR 混入 material[96:112])          │
    │         ▲                 │                                      │
    │         │                 │                                      │
    │    soKey 双向验证 ◄───────┤ round_keys[15] ^ soKey[12:16]        │
    │    (不匹配→delta污染)     │ == EXPECTED? 无分支算术污染           │
    │                           │                                      │
    │    ipc[16] ──────────────┤ (XOR 混入 material[112:128])         │
    │                           │                                      │
    │                           ▼                                      │
    │              ┌─── material[0:64] ──→ round_keys[16]              │
    │              ├─── material[64:80] ──→ configs[16]                │
    │              ├─── material[80:96] ──→ sbox_seeds[4]              │
    │              └─── material[96:100] ─→ delta (可能被 poison)       │
    │                                                                  │
    │              sbox_seeds[4]                                        │
    │                   │                                              │
    │                   ▼                                              │
    │              generate_sbox() × 4 → sboxes[4][256]                │
    │                                                                  │
    │              IV[16] (硬编码)                                      │
    │                   │                                              │
    │                   ▼                                              │
    │              state[16] = IV                                       │
    │                   │                                              │
    │                   ▼  ×16 轮                                       │
    │    ┌──────────────────────────────────────────────────┐          │
    │    │                                                  │          │
    │    │  dynamic_key = (N>=12) ?                         │          │
    │    │    round_keys[N] ^ state[0:4] : round_keys[N] ←─┐          │
    │    │                                             │   │          │
    │    │  sbox_sel = (N<12) ? config[N]              │   │          │
    │    │           : config[N] ^ (state[0] & 0x03) ←─┤   │          │
    │    │                                             │   │          │
    │    │  SubBytes(sbox_sel) → ShiftRows → MixCols   │   │          │
    │    │       → NonLinear(无分支蜜罐D) → AddKey     │   │          │
    │    │                                             │   │          │
    │    │  state[N] ──────────────────────────────────┘   │          │
    │    │       │                                         │          │
    │    │       └─── 反馈到下一轮的 dynamic_key 和 sbox_sel           │
    │    │                                                  │          │
    │    └──────────────────────────────────────────────────┘          │
    │                   │                                              │
    │                   ▼                                              │
    │              final_state[16]                                      │
    │                   │                                              │
    │                   ▼                                              │
    │              expected = ENC_EXPECTED_STATE ^ soKey                │
    │              final_state == expected ?                            │
    │                   │                                              │
    │              YES → "Correct"    NO → "Wrong"                     │
    └──────────────────────────────────────────────────────────────────┘

反馈环路（均仅后4轮生效，round >= 12）:
  ① state[N] → dynamic_key[N]       (后4轮轮密钥反馈)
  ② state[N] → sbox_sel[N]          (后4轮动态S-Box)
  ③ round_keys[15] → delta pollution (soKey双向验证，全局)
```

---

## ==蜜罐触发条件与影响路径==

```
                    ┌─────────────────────────────────────────────┐
                    │           正常执行路径                        │
                    │  (所有全局变量保持初始值)                     │
                    └─────────────────────────────────────────────┘
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          │                             │                             │
    检测点 A                       检测点 B                      检测点 C
    TracerPid≠0                    时间>50ms                    maps有frida
          │                             │                             │
          ▼                             ▼                             ▼
    g_render_mode=1               g_cache_policy=7             g_log_verbosity=0
          │                             │                             │
          ▼                             ▼                             ▼
    蜜罐 A:                        蜜罐 B:                       蜜罐 C:
    spn_round 走                   ARX 只跑 8 轮               shuffle 只做 128 项
    AES 快速路径                   (少 4 轮混合)                (后半恒等)
          │                             │                             │
          └─────────────────────────────┼─────────────────────────────┘
                                        │
                                   检测点 D
                                   BRK 断点存在
                                        │
                                        ▼
                                  g_frame_budget=8.3ms
                                        │
                                        ▼
                                   蜜罐 D:
                                   非线性层退化为 XOR
                                        │
                                        ▼
                              ┌──────────────────────┐
                              │  最终状态不匹配       │
                              │  但程序不崩溃         │
                              │  中间过程看似正常     │
                              └──────────────────────┘
```

**关键隔离性**：
- 蜜罐 A 的 xref：g_render_mode → init.c(写) + spn_round.c(读)，仅此两处
- 蜜罐 B 的 xref：g_cache_policy → key_expand.c 内部(写+读)，完全自包含
- 蜜罐 C 的 xref：g_log_verbosity → sbox_gen.c 内部(写+读)，完全自包含
- 蜜罐 D 的 xref：g_frame_budget_ns → nonlinear.c 内部(写+读)，完全自包含
- 四条路径之间零交叉引用

---

## ==花指令插入位置==

```
花指令应插入在以下函数的入口/关键分支处：

expand_key_material:  入口处 + ARX 循环前
generate_sbox:        入口处 + Fisher-Yates 循环前
spn_round:            蜜罐分支判断前（干扰 IDA 识别分支结构）
nonlinear_feedback:   gf_pow 调用前
honey_tea_path:       入口处（增加 AI 分析时的"真实感"）
honey_aes_path:       入口处

模式：
    cmp xzr, xzr       // 必然相等
    b.ne .+8           // 永远不跳
    .word 0xXXXXXXXX   // 垃圾字节（每处不同值）
    <真实代码>

每处垃圾字节使用不同值，防止模式搜索批量 patch。
```

---

## ==get_func() 间接调用覆盖范围==

以下系统函数通过 get_func() 动态解析，IDA 无法建立交叉引用：

| 函数 | 使用位置 | 目的 |
|------|---------|------|
| mprotect | repair_cfg (方案 A) | 修改代码页权限 |
| clock_gettime | adapt_cache_strategy | 时间检测 |
| fopen / fgets / fclose | adjust_logging | maps 扫描 |
| open / read / close | early_init | status 读取 |
| fork / ptrace / waitpid | get_ipc_material | 子进程校验 |
| ~~memcmp~~ | ~~processInput~~ | 已改为内联常量时间比较，不再通过 get_func |

**不通过 get_func() 的函数**（保持正常 PLT 调用）：
- memcpy / memset — 太常见，隐藏无意义
- 标准 SHA-256 内部运算（仅用于 IPC HMAC）— 不需要隐藏

---

## ==高耦合机制总览==

### 反馈环路

| 编号 | 机制 | 写入位置 | 读取位置 | 效果 |
|------|------|---------|---------|------|
| ① | 轮密钥动态反馈 | 当前 state 输出 | spn_encrypt 第 12~15 轮 | actual_key = round_keys[N] ^ state[0:4]（仅后4轮） |
| ② | S-Box 动态选择 | state[N-1] 输出 | spn_round 第 12~15 轮 | sbox_sel ^= state[0] & 0x03 |
| ③ | soKey 双向验证 | key_schedule 末尾 | delta 值 | diff≠0 → delta ^= 0xDEADBEEF（无分支） |

### 无分支蜜罐

| 蜜罐 | 实现方式 | IDA 可见性 |
|------|---------|-----------|
| A (render_mode) | 显式 if 分支 | 可见（选手突破口） |
| B (cache_policy) | `penalty = (policy != 3) * 4; rounds = 12 - penalty` | CSEL 指令，无跳转 |
| C (log_verbosity) | 显式 if 分支 | 可见（选手突破口） |
| D (frame_budget) | `poison = flag * (correct ^ simple); state = correct ^ poison` | 乘法+XOR，无跳转 |

### key_schedule 中 soKey 双向验证的位置

```
key_schedule()
    │
    ├── expand_key_material()     ← 蜜罐 B (无分支)
    ├── soKey XOR 混入
    ├── IPC 混入
    ├── 派生 round_keys / configs / sbox_seeds / delta
    │
    └── soKey 双向验证:            ← 新增
            check = round_keys[15] ^ *(uint32_t*)&soKey[12]
            diff = check ^ EXPECTED_SOKEY_CHECK
            poison = ((diff | (~diff+1)) >> 31) * 0xDEADBEEF
            delta ^= poison
            // 正确 soKey → poison=0 → delta 不变
            // 错误 soKey → poison=0xDEADBEEF → delta 被污染
```

### 选手解题路径（不受高耦合阻碍）

```
1. 搜索 "Correct" → Java 层 Toast → JNI 调用 nativeProcessInput
2. 逆向 processInput → 发现 fetch_sokey JNI 回调 → 定位 Java deriveNativeKey()
3. 从 APK 提取 .so → CRC32 → 派生 soKey（绕过 Java 层回调）
4. 逆向 key_schedule 的 ARX 结构 → 理解 flag → params 映射
5. 识别蜜罐 A（显式分支）→ 理解 g_render_mode → 发现 constructor 检测
6. 识别蜜罐 C（显式分支）→ 理解 maps 扫描
7. 对比静态/动态执行 → 发现蜜罐 B/D（无分支，需要仔细对比数值）
8. 用正确 soKey 解密 ENC_EXPECTED_STATE → 得到目标 final_state
9. 将完整 pipeline 编码为 Z3 bit-vector 约束，目标 final_state == expected，求解 flag
```

### 成功/失败字符串

```java
// Java 层明文 — 选手可直接搜索定位
if (result == 1) {
    Toast.makeText(this, "Correct! Flag accepted.", Toast.LENGTH_LONG).show();
} else {
    Toast.makeText(this, "Wrong, try again.", Toast.LENGTH_SHORT).show();
}
```

Native 层的蜜罐字符串（"AES-256-CBC" 等）使用多密钥 XOR 加密，6 种 key_source 分散派生。
