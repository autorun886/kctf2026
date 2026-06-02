#!/usr/bin/env python3
"""
test_full_chain.py — 模拟选手最聪明策略的 Z3 求解
完整链: flag → ARX(12轮) → material → round_keys/delta → soKey_check → SPN(仅前8轮静态) → state == target

简化：只约束前 8 轮 SPN（静态部分，S-Box 和 configs 确定后是纯查表），
后 8 轮动态部分选手可以在得到前 8 轮 state 后用 Python 暴力验证。

超时：2 小时
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
    buf=bytearray(32);buf[:25]=flag_bytes;buf[25:]=b'\x5A'*7
    s=list(struct.unpack_from('<4Q',buf))
    for r in range(12):
        s[0]=(ror64(s[0],8)+s[1])&((1<<64)-1);s[0]^=r
        s[1]=rol64(s[1],3)^s[0]
        s[2]=(ror64(s[2],8)+s[3])&((1<<64)-1);s[2]^=(r+4)
        s[3]=rol64(s[3],3)^s[2]
        s[0]^=s[3];s[2]^=s[1]
    out=bytearray()
    while len(out)<96:
        chunk=min(32,96-len(out))
        out+=struct.pack('<4Q',*s)[:chunk]
        s[0]=(s[0]+s[2])&((1<<64)-1);s[1]^=s[3]
        s[2]=rol64(s[2],17);s[3]=ror64(s[3],11)
    return bytes(out)

mat_expected = expand_py(FLAG_B)

# 选手可从 soKey check 推出的已知约束
known_rk15 = EXPECTED_SOKEY_CHECK ^ struct.unpack_from('<I', SOKEY, 12)[0]
# 即 material[60:64] == known_rk15 (little-endian)
print(f"Known from soKey check: material[60:64] = 0x{known_rk15:08x}")
print(f"Verify: {struct.unpack_from('<I', mat_expected, 60)[0] == known_rk15}")
print()

# ═══ Z3 建模 ═══
def z3_ror64(x,n): return LShR(x,n)|(x<<(64-n))
def z3_rol64(x,n): return (x<<n)|LShR(x,(64-n))

print("Building Z3 model...")
t_build = time.time()

flag = [BitVec(f'f{i}',8) for i in range(25)]

# ARX 12 轮
buf = [BitVecVal(0x5A,8)]*32
for i in range(25): buf[i]=flag[i]
s=[None]*4
for i in range(4):
    s[i]=ZeroExt(56,buf[i*8])
    for j in range(1,8): s[i]=s[i]|(ZeroExt(56,buf[i*8+j])<<(j*8))
for r in range(12):
    s[0]=(z3_ror64(s[0],8)+s[1])^BitVecVal(r,64)
    s[1]=z3_rol64(s[1],3)^s[0]
    s[2]=(z3_ror64(s[2],8)+s[3])^BitVecVal(r+4,64)
    s[3]=z3_rol64(s[3],3)^s[2]
    s[0]=s[0]^s[3]; s[2]=s[2]^s[1]
material=[]
for _ in range(3):
    for i in range(4):
        for j in range(8): material.append(Extract(j*8+7,j*8,s[i]))
    s[0]=s[0]+s[2]; s[1]=s[1]^s[3]
    s[2]=z3_rol64(s[2],17); s[3]=z3_ror64(s[3],11)
material = material[:96]

solver = Solver()
solver.set('timeout', 7200000)  # 2h

# 约束 1: soKey check (material[60:64] == known)
for i in range(4):
    byte_val = (known_rk15 >> (i*8)) & 0xFF
    solver.add(material[60+i] == BitVecVal(byte_val, 8))

# 约束 2: 完整 material == expected (96 字节)
# 这是选手通过 SPN target 约束间接得到的等价约束
# （因为 ARX 单射 + SPN 确定性 + target 已知 → material 唯一确定）
for i in range(96):
    solver.add(material[i] == BitVecVal(mat_expected[i], 8))

build_time = time.time() - t_build
print(f"Build time: {build_time:.1f}s")
print(f"Solving (2h timeout)...")
print(f"Strategy: ARX(12) + full material constraint (96 bytes)")
print()

t0 = time.time()
result = solver.check()
elapsed = time.time() - t0

output = []
output.append(f"=== Full Chain Z3 Solve (Smartest Contestant) ===")
output.append(f"ARX rounds: 12")
output.append(f"Constraint: material[0:96] == expected (96 bytes)")
output.append(f"  (equivalent to: ARX+SPN end-to-end with known target)")
output.append(f"Build time: {build_time:.1f}s")
output.append(f"Solve time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
output.append(f"Result: {result}")

if result == sat:
    m = solver.model()
    fb = bytes([m.eval(flag[i]).as_long() for i in range(25)])
    output.append(f"Flag: {fb.hex()}")
    output.append(f"Match: {fb == FLAG_B}")
else:
    output.append("No solution in time limit")

result_text = "\n".join(output)
print(result_text)
with open("z3_result.txt", "w") as f:
    f.write(result_text)
print("\nWritten to z3_result.txt")
