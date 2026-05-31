#!/usr/bin/env python3
"""
make_flag.py — 将方案 A 和方案 B 的 25 字节 flag 交错合并为 50 字节最终 flag。

交错规则：
  output[i*2]   = flagA[i]   (i=0..24)
  output[i*2+1] = flagB[i]   (i=0..24)

用法：py -3 make_flag.py
"""
import base64

# 方案 A flag（precompute_a.py 计算）
FLAG_A_B64 = "IWkqAAEHAAAAjatBObl5N57ewK3eB0ITNw=="
# 方案 B flag（precompute_b.py 计算）
FLAG_B_B64 = "S0NURjIwMjZfQl92MV8yMDI2X0FVVE9DVA=="

flagA = base64.b64decode(FLAG_A_B64)
flagB = base64.b64decode(FLAG_B_B64)
assert len(flagA) == 25 and len(flagB) == 25

# 交错合并
output = bytearray(50)
for i in range(25):
    output[i * 2]     = flagA[i]
    output[i * 2 + 1] = flagB[i]

print(f"flagA (hex): {flagA.hex()}")
print(f"flagB (hex): {flagB.hex()}")
print(f"\n50-byte flag (hex): {output.hex()}")
print(f"50-byte flag (b64): {base64.b64encode(output).decode()}")
