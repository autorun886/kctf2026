#!/usr/bin/env python3
"""
test_arx_rounds.py — 测试 15 轮 ARX 的 Z3 求解时间
超时设置 2 小时，结果输出到 z3_result.txt
"""
import time, struct
from z3 import *

FLAG_B = bytes([0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
                0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
                0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])

def ror64(x,n): return ((x>>n)|(x<<(64-n)))&((1<<64)-1)
def rol64(x,n): return ((x<<n)|(x>>(64-n)))&((1<<64)-1)

def expand_py(flag_bytes, rounds):
    buf = bytearray(32); buf[:25]=flag_bytes; buf[25:]=b'\x5A'*7
    s = list(struct.unpack_from('<4Q', buf))
    for r in range(rounds):
        s[0]=(ror64(s[0],8)+s[1])&((1<<64)-1); s[0]^=r
        s[1]=rol64(s[1],3)^s[0]
        s[2]=(ror64(s[2],8)+s[3])&((1<<64)-1); s[2]^=(r+4)
        s[3]=rol64(s[3],3)^s[2]
        s[0]^=s[3]; s[2]^=s[1]
    out = bytearray()
    while len(out)<96:
        chunk=min(32,96-len(out))
        out+=struct.pack('<4Q',*s)[:chunk]
        s[0]=(s[0]+s[2])&((1<<64)-1); s[1]^=s[3]
        s[2]=rol64(s[2],17); s[3]=ror64(s[3],11)
    return bytes(out)

def z3_ror64(x,n): return LShR(x,n)|(x<<(64-n))
def z3_rol64(x,n): return (x<<n)|LShR(x,(64-n))

ROUNDS = 15
TIMEOUT_MS = 7200000  # 2 hours

print(f"Testing {ROUNDS}-round ARX Z3 solve")
print(f"Timeout: {TIMEOUT_MS//1000}s ({TIMEOUT_MS//60000} min)")
print(f"Flag: {FLAG_B.hex()}")
print()

expected = expand_py(FLAG_B, ROUNDS)
print(f"Expected material[0:16] = {expected[:16].hex()}")

flag = [BitVec(f'f{i}',8) for i in range(25)]
buf = [BitVecVal(0x5A,8)]*32
for i in range(25): buf[i]=flag[i]
s=[None]*4
for i in range(4):
    s[i]=ZeroExt(56,buf[i*8])
    for j in range(1,8): s[i]=s[i]|(ZeroExt(56,buf[i*8+j])<<(j*8))
for r in range(ROUNDS):
    s[0]=(z3_ror64(s[0],8)+s[1])^BitVecVal(r,64)
    s[1]=z3_rol64(s[1],3)^s[0]
    s[2]=(z3_ror64(s[2],8)+s[3])^BitVecVal(r+4,64)
    s[3]=z3_rol64(s[3],3)^s[2]
    s[0]=s[0]^s[3]; s[2]=s[2]^s[1]
out=[]
for _ in range(3):
    for i in range(4):
        for j in range(8): out.append(Extract(j*8+7,j*8,s[i]))
    s[0]=s[0]+s[2]; s[1]=s[1]^s[3]
    s[2]=z3_rol64(s[2],17); s[3]=z3_ror64(s[3],11)

solver = Solver()
solver.set('timeout', TIMEOUT_MS)
for i in range(96):
    solver.add(out[i]==BitVecVal(expected[i],8))

print(f"Constraints built. Solving...")
t0=time.time()
result=solver.check()
elapsed=time.time()-t0

output = []
output.append(f"ARX rounds: {ROUNDS}")
output.append(f"Result: {result}")
output.append(f"Time: {elapsed:.1f}s ({elapsed/60:.1f} min)")

if result==sat:
    m=solver.model()
    fb=bytes([m.eval(flag[i]).as_long() for i in range(25)])
    output.append(f"Flag: {fb.hex()}")
    output.append(f"Match: {fb==FLAG_B}")
else:
    output.append(f"No solution (timeout or unsat)")

result_text = "\n".join(output)
print(result_text)

with open("z3_result.txt", "w") as f:
    f.write(result_text)
print("\nWritten to z3_result.txt")
