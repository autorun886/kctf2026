# 2026 KCTF 题目设计文档（最终版）

## 概述

- **题目类型**：Android ARM64 逆向
- **输入格式**：100 个十六进制字符（50 字节）
- **验证方式**：正确输入显示 "Correct! Flag accepted."
- **预计解题时间**：10-16 小时（顶尖选手 8h）
- **核心难点**：结构修复 + 参数化 SPN 约束求解 + 反动态分析

---

## 架构

```
用户输入 (100 hex chars = 50 bytes)
    │
    ▼ hexDecode
50 bytes → 交错拆分
    ├── flagA[25] = input[0,2,4,...,48]  (偶数位)
    └── flagB[25] = input[1,3,5,...,49]  (奇数位)
    │
    ▼ JNI: nativeProcessInput
    │
    ├── fetch_sokey (JNI 回调 Java deriveNativeKey)
    │       └── APK 内 libkctf.so .text CRC32 → LCG 扩展 → soKey[16]
    │
    ├── verify_scheme_a(flagA, soKey)  ← 必须先通过
    │       └── repair_cfg → repair_sbox → repair_constants → repair_semantics
    │           → core_compute → 比对 ENC_EXPECTED_STATE_A ^ soKey
    │
    └── verify_scheme_b(flagB, soKey)
            └── key_schedule(ARX 16轮) → generate_sbox ×4 → spn_encrypt ×2(双IV)
                → 比对 ENC_EXPECTED_STATE ^ soKey + ENC_EXPECTED_STATE2 ^ soKey
```

---

## 方案 A：显式修复（flagA[25]）

### Flag 布局

| 字节 | 用途 | 约束来源 |
|------|------|---------|
| [0:4] | BB0→BB1 跳转偏移 | 编译时 BB 地址固定 |
| [4] | TBZ bit field (低4bit) | 必须为 0x01 |
| [5:9] | BB4→BB5 跳转偏移 | dead block 跳过 |
| [9:13] | BB6 adr imm21 (XOR soKey[0:4]) | BB7 入口地址 |
| [13:17] | XTEA delta | KPT/KCT 3组明密文对 |
| [17:21] | LCG seed (混入 sbox[0]) | KPT/KCT 同上 |
| [21] | step2 循环移位量 (5bit) | KIN/KOUT 8组IO对 |
| [22:25] | step3 参数 | KIN/KOUT 同上 |

### 修复链依赖

```
repair_cfg(flag, soKey)
    ↓ dispatch_table[0] & 0xFF
repair_sbox(flag, cfg_dep)
    ↓ sbox_shipped[0]
repair_constants(flag, sbox_first)
    ↓ round_constants[0] >> 28
repair_semantics(flag, rc_high4)
    ↓
core_compute(state) → final_state
```

每步输出作为下一步输入，选手必须按序求解。

---

## 方案 B：隐式修复（flagB[25]）

### Pipeline

```
flagB[25] → expand_key_material(16轮 ARX) → material[96]
    + soKey XOR → material[96:112]
    → round_keys[16], configs[16], sbox_seeds[4], delta
    → generate_sbox ×4
    → spn_encrypt(IV1, 16轮) → state1 == ENC_EXPECTED_STATE ^ soKey
    → spn_encrypt(IV2, 16轮) → state2 == ENC_EXPECTED_STATE2 ^ soKey
```

### SPN 结构（每轮）

1. **SubBytes**：4 个 Fisher-Yates S-Box，由 config 选择
2. **ShiftRows**：4 种模式
3. **MixColumns**：4 个 MDS 矩阵 (GF(2^8))
4. **NonlinearFeedback**：GF(2^8) 幂次 {7,11,13,23}
5. **AddRoundKey**：32-bit key 扩展 XOR 到 16 字节

### 动态机制（round >= 8）

- **轮密钥反馈**：`dynamic_key ^= state[0:4]`
- **S-Box 动态选择**：`sbox_sel = (config ^ state[0]) & 0x03`

前 8 轮完全静态（Z3 可直接展开），后 8 轮需联合约束求解。

---

## 反调试/反注入体系（8 层）

| 蜜罐 | 检测目标 | 触发条件 | 分支类型 | 污染效果 |
|------|---------|---------|---------|---------|
| A | 调试器 | TracerPid≠0 (加载时) | 显式 if | SPN 走 AES 路径 |
| A2 | 调试器 | TracerPid≠0 (执行时) | 无分支 XOR | round_key ^= 0xA5A5A5A5 |
| B | 时间膨胀 | >50ms (key_schedule) | 无分支 CSEL | ARX 少 4 轮 |
| B2 | 单步调试 | >200ms/4轮 (SPN中) | 无分支乘法 | nonlinear 退化 |
| C | Frida注入 | maps 关键字 + 大匿名内存>2MB | 显式 if | S-Box 半 shuffle |
| D | 软件断点 | BRK 指令扫描 | 无分支乘法 | nonlinear 退化 |
| E | Unicorn模拟 | getauxval HWCAP 缺失 | 无分支 XOR | round_key ^= 0x5A5A5A5A |
| F | Inline Hook | libc 函数头有跳转指令 | 无分支 XOR | delta ^= 0xCAFECAFE |

---

## AI 蜜罐

| 诱饵 | 位置 | AI 的错误判断 |
|------|------|-------------|
| `honey_tea_path` + HONEY_DELTA(0x9E3779B8) | tea_impl.c | "这是 TEA 加密" |
| `honey_aes_path` + AES_SBOX + 10轮结构 | aes_impl.c | "这是 AES-128" |
| ChaCha20 sigma 常量 | tea_impl.c | "程序使用 ChaCha20" |
| SHA-256 H0~H7 常量 | tea_impl.c | "有 SHA-256 校验" |
| `check_debug_bypass` + DEBUG_MAGIC | tea_impl.c | "发现调试后门" |
| 函数名 `chacha20_quarter_round` | key_expand.c 注释 | "ARX 是 ChaCha20" |
| 函数名 `sm4_L_transform` | spn_round.c 注释 | "非线性层是 SM4" |
| 函数名 `aes_sbox_init` | sbox_gen.c 注释 | "S-Box 是 AES 的" |

---

## soKey 派生

```java
// Java 层 deriveNativeKey()
1. 从 APK 中提取 lib/arm64-v8a/libkctf.so
2. 解析 ELF，定位 .text section
3. CRC32(.text) → crcVal
4. LCG 扩展：for i in 0..3:
     m = (crcVal ^ EXPAND[i]) * 0x5851F42D4C957F2D + 0x14057B7EF767814F
     key[i*4 : i*4+4] = m >> 24 的高 4 字节
```

**安全意义**：Frida inline hook 修改 .text → CRC 变化 → soKey 错误 → 全链路失败。

---

## Flag 唯一性保证

- **方案 B**：200-bit 输入 vs 256-bit 约束（双 IV）→ 过约束 → 唯一
- **方案 A**：每段独立过约束（KPT/KCT 192bit > 64bit, KIN/KOUT 256bit > 32bit）
- **ARX 单射性**：16 轮 ARX 是 256-bit 状态空间上的双射，限制在 200-bit 子集上仍为单射
