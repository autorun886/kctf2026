# Plan: Oracle XOR Key 3-Share 保护

## 目标
将 `get_oracle_key()` 的单一 Feistel 派生改为 3-share XOR 组合：
```
final_key = share_0 ⊕ share_1 ⊕ share_2
```
选手必须同时还原三条路径才能得到正确的 16 字节 XOR key。

## 三个 Share 的设计

### Share 0: MBA 混淆的常量派生（替代当前 _kdf_iv + Feistel）
- 去掉 `_kdf_iv[8]` 数组（太容易被 IDA 交叉引用定位）
- 常量直接编码为 MOVZ/MOVK 指令流中的 immediate
- 派生函数用 MBA（Mixed Boolean-Arithmetic）混淆：
  ```c
  // MBA 恒等式示例：x + y == (x ^ y) + 2*(x & y)
  // 反编译器输出一堆位运算，人/AI 难以化简
  static uint32_t mba_transform(uint32_t x, uint32_t k) {
      uint32_t a = (x ^ k) + 2 * (x & k);         // == x + k
      a = ((a ^ (a >> 16)) + 2*(a & (a >> 16)));   // 看起来复杂但可化简
      a = a * 0x45D9F3B;
      a ^= (a >> 16);
      return a;
  }
  ```
- 输出 8 字节（share_0[0:8]），剩余 8 字节留给 share_1/2 覆盖

### Share 1: Self-Referential（.text 函数哈希）
- 对 `expand_key_material` 函数的前 64 字节机器码做 CRC32 变换
- 结果作为 share_1（8 字节）
- **效果**：patch 任何 `expand_key_material` 代码→hash 变→key 错→shellcode 解密为垃圾
- 访问方式：`(uint32_t*)(void*)expand_key_material` 读取函数地址处的代码字节
- 无需额外数据段

### Share 2: 绑定 soKey（APK 完整性）
- `share_2 = some_transform(soKey[0:8])`
- soKey 来自 Java 层 CRC32(.text)→LCG，选手已能计算
- 但这意味着 key 绑定到特定 APK build——替换 .so 会导致 soKey 变→share_2 变→key 错
- 访问方式：通过 JNI 回调 fetch_sokey（已有），或从 key_schedule 参数中取

## 文件修改

### `seeds_oracle.c`
1. 删除 `_kdf_iv[8]` 数组
2. 重写 `get_oracle_key()`：
   - share_0: 用 MBA 混淆的内联常量计算 8 字节
   - share_1: 读取 `expand_key_material` 函数头 64 字节，CRC32 变换得 8 字节
   - share_2: 从全局 `g_sokey_cache`（由 jni_entry 写入）取 soKey 前 8 字节做简单变换
   - `out[i] = share_0[i] ^ share_1[i] ^ share_2[i]`
3. 保留蜜罐逻辑（g_cached_key / g_key_debug_override）不变

### `jni_entry.c`
- 在 `fetch_sokey` 后将 soKey 写入一个 `seeds_oracle.c` 可访问的全局变量
- 或：将 soKey 传递给 `get_oracle_material` 函数

### `converge.py`
- `compute_oracle_xor_key()` 重写：
  - share_0: 复刻 MBA 逻辑
  - share_1: 从 .so 读取 expand_key_material 函数前 64 字节，计算 CRC32
  - share_2: 用 soKey 前 8 字节计算
  - final_key = share_0 ^ share_1 ^ share_2

### `kctf.h`
- `get_oracle_material` 签名可能需要接收 soKey 参数（或用全局变量）

## 注意事项
- share_1 读取的是 .text 中的机器码，不影响 .text CRC（只读不写）
- share_1 会让 key 随编译变化（函数代码不同→hash 不同→key 不同）
  - 这正是我们想要的：converge.py 每次构建后重新计算 key
  - 但这意味着 oracle section 的 XOR key 每次编译都不同→converge.py 必须后处理
- 选手做法：IDA 中读 expand_key_material 前 64 字节机器码→本地计算 CRC→得到 share_1

## 选手求解路径
1. 逆向 `get_oracle_key`：识别 3-share 结构
2. Share 0：从 MBA 混淆代码中提取常量值（需化简 MBA 或直接模拟执行）
3. Share 1：从 IDA 中读 expand_key_material 前 64 字节→CRC32
4. Share 2：计算 soKey（已有能力）→变换
5. XOR 三个 share → 得到 16 字节 key → 解密 shellcode
