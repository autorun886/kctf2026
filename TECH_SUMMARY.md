# 2026 KCTF 核心技术总结

## 一、题目概况

| 项目 | 值 |
|------|-----|
| 平台 | Android ARM64 (Pixel 6, API 29+) |
| 输入 | 100 个十六进制字符 = 50 字节 |
| 验证 | Toast "Correct! Flag accepted." |
| .so 大小 | ~21KB, .text ~13KB (3360 条指令) |
| IDA 可见函数 | 9 个用户函数 + 13 个 PLT 导入 |
| 预计解题时间 | 10-16h |

---

## 二、核心架构

```
50 bytes hex input
    │ hexDecode
    ▼
flagA[25] = even bytes ──→ verify_scheme_a ──→ 修复链 + XTEA 变体
flagB[25] = odd bytes  ──→ verify_scheme_b ──→ ARX + SPN(16轮, 双IV)
    │                              │
    │  soKey = CRC32(.text) → LCG  │
    │         (JNI 回调获取)        │
    ▼                              ▼
方案 A 通过 && 方案 B 通过 → return 1
```

**关键设计**：
- 50 字节交错拆分（NEON `vld2` 优化，IDA 不易识别）
- soKey 由 native 层 JNI 回调 Java 层获取（不在参数列表中暴露）
- 方案 A 必须先通过才执行方案 B（串行依赖）

---

## 三、方案 A — 显式修复链

### 修复链拓扑

```
repair_cfg(flag[0:13], soKey)
    ↓ dispatch_table[0] & 0xFF
repair_sbox(flag[9:13], cfg_dep)
    ↓ sbox_shipped[0]
repair_constants(flag[13:21], sbox_first)
    ↓ round_constants[0] >> 28
repair_semantics(flag[21:25], rc_high4)
    ↓
core_compute(state) → 比对 ENC_EXPECTED_STATE_A ^ soKey
```

### 核心技术点

1. **非线性耦合**：每步输出作为下一步输入参数，不可独立求解
2. **XTEA 变体**：标准 Feistel 结构 + 自定义 step2(循环左移) + step3(非线性混合)
3. **已知对约束**：3 组 KPT/KCT (192-bit) + 8 组 KIN/KOUT (256-bit) 保证唯一性
4. **SBOX_CHECK[3]**：3 字节已知对，将 S-Box seed 有效空间从 ~1.6 亿压缩到 ~1

---

## 四、方案 B — 隐式修复 (参数化 SPN)

### Pipeline

```
flagB[25]
    ↓ expand_key_material (16 轮 ARX, Speck-like)
material[96]
    ↓ + soKey XOR
round_keys[16], configs[16], sbox_seeds[4], delta
    ↓ Fisher-Yates × 4
sboxes[4][256]
    ↓ spn_encrypt(IV1) + spn_encrypt(IV2)
state1[16], state2[16]
    ↓ 比对 ENC_EXPECTED_STATE/STATE2 ^ soKey
PASS/FAIL
```

### 核心技术点

1. **16 轮 ARX 密钥扩展**：ROR64(8) + ADD + XOR + ROL64(3) + 跨半区混合，密码学强度单射
2. **参数化 SPN**：每轮 4 个 2-bit 选择器决定 S-Box/ShiftRows/MDS/NonlinearMode
3. **动态轮 (round >= 8)**：
   - 轮密钥反馈：`dynamic_key ^= state[0:4]`
   - S-Box 动态选择：`sel = (config ^ state[0]) & 3`
   - 中间状态 CRC 混入：`dynamic_key ^= CRC32(state_at_round8)`
4. **双 IV 唯一性**：256-bit 约束 > 200-bit 输入 → 数学保证唯一解
5. **GF(2^8) 非线性层**：幂次 {7,11,13,23}（全双射，Z3 每个约束有唯一解路径）
6. **MDS[1]/MDS[2] 奇异**：行列式为 0，封死逆推路径，强制正向建模

---

## 五、反动态分析体系 (8 层蜜罐)

| 蜜罐 | 检测目标 | 检测方式 | 分支类型 | 污染效果 |
|------|---------|---------|---------|---------|
| A | 调试器 (加载时) | /proc/self/status TracerPid | 显式 if | SPN 走 AES 路径 |
| A2 | 调试器 (执行时) | /proc/self/status TracerPid | 无分支 XOR | round_key ^= 0xA5A5A5A5 |
| B | 时间膨胀 | clock_gettime 1000 次循环 | 无分支 CSEL | ARX 少 4 轮 (16→12) |
| B2 | 单步调试 | 每 4 轮 clock_gettime 采样 | 无分支乘法 | nonlinear 退化为 XOR |
| C | Frida/注入 | /proc/self/maps 关键字 + 大匿名内存>2MB | 显式 if | S-Box 半 shuffle (128/256) |
| D | 软件断点 | .text BRK 指令扫描 | 无分支乘法 | nonlinear 退化为 XOR |
| E | Unicorn 模拟 | getauxval(AT_HWCAP) FP+ASIMD | 无分支 XOR | round_key ^= 0x5A5A5A5A |
| F | Inline Hook | libc 函数头 B/LDR 指令检测 | 无分支 XOR | delta ^= 0xCAFECAFE |

### 关键设计原则

- **无分支蜜罐 (B/B2/D/E/F)**：IDA 看不到条件跳转，AI 无法通过 CFG 识别
- **显式分支蜜罐 (A/C)**：作为选手突破口，引导理解蜜罐机制
- **分散全局变量**：每个蜜罐独立变量，xref 不互相关联
- **静默污染**：不崩溃不退出，产出"看似正确但错误"的结果

---

## 六、反 Unicorn/符号执行

### 中间状态 CRC 混入

```c
if (round == 8) {
    state_crc_mix = state_checksum(state);  // CRC32 of 16-byte state
}
if (round >= 8) {
    dynamic_key ^= state_crc_mix;  // 后 8 轮全部受影响
}
```

**效果**：
- Unicorn 必须完整正确模拟前 8 轮才能得到正确的 state_crc_mix
- 任何一个环节（S-Box、MDS、round_key）有误差 → CRC 错 → 后 8 轮全错
- 等价于要求选手写出完整正确的 SPN 模拟器（与手写求解器等价）

### HWCAP 环境指纹

```c
unsigned long hwcap = getauxval(16);  // AT_HWCAP
g_hwcap_mask = ((hwcap & 0x3) == 0x3) ? 0 : 0x5A5A5A5Au;
```

Unicorn 默认 `getauxval` 返回 0 → 所有 round_key 被 XOR 污染。

---

## 七、AI 蜜罐体系

### 命名误导

| 实际功能 | 伪装名 | AI 判断 |
|---------|--------|---------|
| ARX 密钥扩展 | chacha20_quarter_round | ChaCha20 |
| Fisher-Yates S-Box | aes_sbox_init | AES S-Box |
| GF(2^8) 幂次 | sm4_L_transform | SM4 线性变换 |
| 蜜罐 TEA 路径 | tea_encrypt_block | TEA 加密 |

### 常量误导

- ChaCha20 sigma (`0x61707865...`) — 蜜罐路径使用
- AES Rcon 表 — 蜜罐路径使用
- SHA-256 H0~H7 — 蜜罐路径使用
- TEA delta 0x9E3779B8 (差 1) — 蜜罐路径使用

### 结构误导

- `honey_tea_path`：完整 32 轮 TEA 结构，但 delta 差 1
- `honey_aes_path`：完整 10 轮 AES 结构，但 S-Box 是恒等映射
- `check_debug_bypass` + `DEBUG_MAGIC`：假调试后门

### 实战验证

AI 生成的求解脚本（见 solve_full.py）：
- ✅ 正确识别了 LCG 常量
- ❌ 建模为标准 XTEA（缺失 step2/step3）
- ❌ 不知道 sbox_first 耦合
- ❌ 完全忽略方案 B
- ❌ 使用旧版本常量

---

## 八、soKey 防篡改机制

### 派生流程

```
APK 内 libkctf.so → 解析 ELF → .text section → CRC32 → LCG 扩展 → soKey[16]
```

### 三重校验

1. **Java 层 CRC**：deriveNativeKey() 从 APK 读取 .so 计算
2. **soKey 双向验证**：`round_keys[15] ^ soKey[12:16] == EXPECTED_SOKEY_CHECK`，不匹配 → `delta ^= 0xDEADBEEF`
3. **Inline Hook 检测**：libc 函数头被修改 → `delta ^= 0xCAFECAFE`

**效果**：Frida inline hook 修改 .text → CRC 变 → soKey 错 → 双向验证失败 → delta 被污染 → 全链路错误。

---

## 九、动态函数调用

### resolver.c 覆盖

8 个系统函数通过加密函数名 + `dlsym` 动态解析：

| ID | 函数 | 使用位置 |
|----|------|---------|
| 0 | clock_gettime | 蜜罐 B/B2 时间检测 |
| 1 | fopen | 蜜罐 C maps 扫描 |
| 2 | fgets | 蜜罐 C maps 扫描 |
| 3 | fclose | 蜜罐 C maps 扫描 |
| 4 | open | 蜜罐 A2 status 读取 |
| 5 | read | 蜜罐 A2 status 读取 |
| 6 | close | 蜜罐 A2 status 读取 |
| 7 | mprotect | 蜜罐 F hook 检测 |

**效果**：IDA 无法建立 xref，看不到这些函数的调用关系。

### PLT 残留（不可避免）

- `dlsym` — resolver.c 必需
- `getauxval` — 蜜罐 E 必需
- `strstr` — maps 扫描中使用
- `__open_2/read/close` — init.c constructor（加载时执行，get_func_by_id 尚未初始化）

---

## 十、花指令（输入驱动不透明谓词）

```c
// nativeProcessInput 入口：
g_opaque = input[0];  // 用户输入的第一个字节

// 各函数中的花指令：
{ volatile uint32_t _a = g_opaque; volatile uint32_t _b = g_opaque;
__asm__ volatile(
    "cmp %w0, %w1\n\t"    // 比较两次 volatile 读取（运行时恒等）
    "b.eq 1f\n\t"          // IDA 不知道相等，必须分析两条路径
    ".word 0xDEADBEEF\n\t" // 垃圾字节
    "1:\n\t"
    :: "r"(_a), "r"(_b) : "cc"
); }
```

**为什么 IDA 无法优化**：
- `g_opaque` 是 `volatile` 全局变量，两次读取可能不同（IDA 必须保守假设）
- 值来自用户输入 `input[0]`，静态分析时完全未知
- 即使 IDA 猜测两次读取相等，也无法证明（volatile 语义）

**为什么选手不能 patch**：
- `input[0]` 同时是 `flagA[0]`，参与方案 A 的 `repair_cfg` 验证
- Patch `g_opaque` 赋值 → `input[0]` 不再正确传递 → 方案 A 失败
- Patch .text 任何字节 → soKey CRC 变化 → 全链路失败

每处使用不同垃圾值（0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D 等），防止模式搜索批量 NOP。

---

## 十一、Flag 唯一性保证

### 方案 B

- 输入空间：200 bit
- 约束空间：256 bit（双 IV × 128 bit）
- ARX 单射性：16 轮双射限制在 200-bit 子集上仍为单射
- 结论：**数学保证唯一**

### 方案 A

- 每段独立过约束：
  - BB 地址：1/2^26 命中概率
  - SBOX_CHECK：24-bit 约束 32-bit seed
  - KPT/KCT：192-bit 约束 64-bit (delta+seed)
  - KIN/KOUT：256-bit 约束 32-bit (step2+step3)
- 结论：**多层过约束保证唯一**

---

## 十二、编译与构建

| 配置 | 值 |
|------|-----|
| NDK | 27.0, arm64-v8a only |
| 编译标志 | `-fno-lto -fno-merge-all-constants -fvisibility=hidden` |
| ProGuard | 启用，保留 JNI 入口 + deriveNativeKey |
| 签名 | kctf2026.jks |
| 收敛工具 | converge.py (自动 Build → CRC → 常量更新 → Rebuild → 验证) |

---

## 十三、选手合法解题路径

1. 搜索 "Correct" → Java 层 → JNI 入口
2. 逆向 fetch_sokey → JNI 回调 → deriveNativeKey → 从 APK 提取 .so → CRC32 → soKey
3. 识别交错拆分（NEON vld2）
4. 方案 A：从 .so 提取 BB 地址 → 逐步求解修复链
5. 方案 B：逆向 ARX → 理解 SPN → Z3 建模（前 8 轮静态 + 后 8 轮动态 + CRC 混入）
6. Z3 求解（预计 4-6h 计算时间）
7. 交错合并 flagA + flagB → hex 编码提交
