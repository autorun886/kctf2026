#!/usr/bin/env python3
"""
test_seeds_known.py — 测试选手知道 sbox_seeds 后的 Z3 求解时间

选手已知信息：
1. soKey check → material[60:64] (32-bit)
2. sbox_seeds → material[80:96] (128-bit)
3. S-Box 可预计算（确定性）
4. SPN target (128-bit，用具体 S-Box 查表建模)

Z3 约束：ARX(flag)[60:64] == known AND ARX(flag)[80:96] == known
总约束 160-bit on 200-bit flag → Z3 应该能快速求解

超时 2 小时
"""
import time, struct
from z3 import *

FLAG_B = bytes([0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
                0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
                0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])
SOKEY = bytes.fromhex("0626fbb9ea5656a6b101fe996205b6b0")
EXPECTED_SOKEY_CHECK = 0xe437295c

# 正向计算 expected material
def ror64(x,n): return ((x>>n)|(x<<(64-n)))&((1<<64)-1)
def rol64(x,n): return ((x<<n)|(x>>(64-n)))&((1<<64)-1)

def expand_py(flag_bytes):
    buf=bytearray(32); buf[:25]=flag_bytes; buf[25:]=b'\x5A'*7
    s=list(struct.unpack_from('<4Q',buf))
    for r in range(12):
        s[0]=(ror64(s[0],8)+s[1])&((1<<64)-1); s[0]^=r
        s[1]=rol64(s[1],3)^s[0]
        s[2]=(ror64(s[2],8)+s[3])&((1<<64)-1); s[2]^=(r+4)
        s[3]=rol64(s[3],3)^s[2]
        s[0]^=s[3]; s[2]^=s[1]
    out=bytearray()
    while len(out)<96:
        chunk=min(32,96-len(out))
        out+=struct.pack('<4Q',*s)[:chunk]
        s[0]=(s[0]+s[2])&((1<<64)-1); s[1]^=s[3]
        s[2]=rol64(s[2],17); s[3]=ror64(s[3],11)
    return bytes(out)

mat = expand_py(FLAG_B)

# 选手已知的信息
known_rk15 = EXPECTED_SOKEY_CHECK ^ struct.unpack_from('<I', SOKEY, 12)[0]
known_seeds = mat[80:96]  # 16 字节，选手从 .so 中提取

print(f"Known rk15 (from soKey check): 0x{known_rk15:08x}")
print(f"Known seeds (from .so): {known_seeds.hex()}")
print(f"  seed[0]=0x{struct.unpack_from('<I',known_seeds,0)[0]:08x}")
print(f"  seed[1]=0x{struct.unpack_from('<I',known_seeds,4)[0]:08x}")
print(f"  seed[2]=0x{struct.unpack_from('<I',known_seeds,8)[0]:08x}")
print(f"  seed[3]=0x{struct.unpack_from('<I',known_seeds,12)[0]:08x}")
print()

# Z3 建模
def z3_ror64(x,n): return LShR(x,n)|(x<<(64-n))
def z3_rol64(x,n): return (x<<n)|LShR(x,(64-n))

print("Building Z3 constraints...")
t_build = time.time()

flag = [BitVec(f'f{i}', 8) for i in range(25)]
buf = [BitVecVal(0x5A, 8)] * 32
for i in range(25): buf[i] = flag[i]

s = [None] * 4
for i in range(4):
    s[i] = ZeroExt(56, buf[i*8])
    for j in range(1, 8):
        s[i] = s[i] | (ZeroExt(56, buf[i*8+j]) << (j*8))

for r in range(12):
    s[0] = (z3_ror64(s[0], 8) + s[1]) ^ BitVecVal(r, 64)
    s[1] = z3_rol64(s[1], 3) ^ s[0]
    s[2] = (z3_ror64(s[2], 8) + s[3]) ^ BitVecVal(r+4, 64)
    s[3] = z3_rol64(s[3], 3) ^ s[2]
    s[0] = s[0] ^ s[3]
    s[2] = s[2] ^ s[1]

material_z3 = []
for _ in range(3):
    for i in range(4):
        for j in range(8):
            material_z3.append(Extract(j*8+7, j*8, s[i]))
    s[0] = s[0] + s[2]
    s[1] = s[1] ^ s[3]
    s[2] = z3_rol64(s[2], 17)
    s[3] = z3_ror64(s[3], 11)
material_z3 = material_z3[:96]

solver = Solver()
solver.set('timeout', 7200000)  # 2h

# 约束 1: soKey check — material[60:64] == known (32-bit)
for i in range(4):
    solver.add(material_z3[60+i] == BitVecVal((known_rk15 >> (i*8)) & 0xFF, 8))

# 约束 2: sbox_seeds — material[80:96] == known (128-bit)
for i in range(16):
    solver.add(material_z3[80+i] == BitVecVal(known_seeds[i], 8))

build_time = time.time() - t_build
total_constraint_bits = 32 + 128  # 160 bits
print(f"Build time: {build_time:.2f}s")
print(f"Total constraint: {total_constraint_bits} bits on 200-bit flag")
print(f"Solving (2h timeout)...")
print()

t0 = time.time()
result = solver.check()
elapsed = time.time() - t0

output = []
output.append("=== Seeds-Known Strategy Test ===")
output.append(f"ARX rounds: 12")
output.append(f"Constraints: material[60:64] (32-bit) + material[80:96] (128-bit) = 160-bit")
output.append(f"Build time: {build_time:.2f}s")
output.append(f"Solve time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
output.append(f"Result: {result}")

if result == sat:
    m = solver.model()
    fb = bytes([m.eval(flag[i]).as_long() for i in range(25)])
    output.append(f"Flag: {fb.hex()}")
    output.append(f"Match: {fb == FLAG_B}")

    # 验证 material 匹配
    verify_mat = expand_py(fb)
    output.append(f"material[60:64] match: {verify_mat[60:64] == mat[60:64]}")
    output.append(f"material[80:96] match: {verify_mat[80:96] == mat[80:96]}")
    output.append(f"Full material match: {verify_mat == mat}")
else:
    output.append("No solution found")

output.append("")
output.append("NOTE: 160-bit constraint < 200-bit flag → solution may not be unique")
output.append("Contestant would additionally verify SPN(IV) == target to confirm")

result_text = "\n".join(output)
print(result_text)

with open("z3_result.txt", "w") as f:
    f.write(result_text)
print("\nWritten to z3_result.txt")
