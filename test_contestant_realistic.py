#!/usr/bin/env python3
"""
test_contestant_realistic.py — 选手实际可行的求解策略

选手知道：
- soKey check: material[60:64] == EXPECTED_SOKEY_CHECK ^ soKey[12:16] (4 字节)
- target_state = ENC ^ soKey (16 字节)
- ARX/SPN/Fisher-Yates 完整结构

策略：Z3 约束 ARX + soKey check (32-bit)，枚举所有满足解，
     每个解用 Python 正向跑 SPN 验证是否 == target。

由于 200-bit flag 只有 32-bit 约束，理论上有 2^168 个解。
但 Z3 找到的第一个解不太可能是正确 flag。
实际上选手需要加更多约束才能缩小搜索空间。

更聪明的策略：选手额外约束 delta 值。
delta = material[96:100] = material[0:4] ^ soKey[0:4]
如果选手能猜到 delta 的范围... 不行，delta 是任意 32-bit。

最终策略：选手必须把 SPN 也放进 Z3。
本脚本测试：ARX(12轮) + material 全 96 字节约束（上界，~8.5min）
这等价于选手把 SPN 建模正确后 Z3 能推导出的等价约束。

超时 2 小时。
"""
import time, struct
from z3 import *

FLAG_B = bytes([0x7A,0xE3,0x1B,0x94,0xD2,0x56,0xF8,0x0C,
                0x41,0xB7,0x29,0x8E,0x63,0xA5,0xDF,0x10,
                0x4B,0xC8,0x72,0x3D,0x96,0x0F,0xE4,0x58,0xAD])
SOKEY = bytes.fromhex("0626fbb9ea5656a6b101fe996205b6b0")
EXPECTED_SOKEY_CHECK = 0xe437295c
IV1 = bytes([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
             0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10])

NL_POWER = [7, 11, 13, 23]
MDS = [[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]],
       [[5,3,4,2],[2,5,3,4],[4,2,5,3],[3,4,2,5]],
       [[7,6,2,3],[3,7,6,2],[2,3,7,6],[6,2,3,7]],
       [[9,14,5,4],[4,9,14,5],[5,4,9,14],[14,5,4,9]]]
SHIFTS = [[0,1,2,3],[0,1,3,4],[0,2,3,1],[0,3,1,2]]

def ror64(x,n): return ((x>>n)|(x<<(64-n)))&((1<<64)-1)
def rol64(x,n): return ((x<<n)|(x>>(64-n)))&((1<<64)-1)
def gf_mul(a,b):
    r=0
    for _ in range(8):
        if b&1: r^=a
        hi=a&0x80; a=(a<<1)&0xFF
        if hi: a^=0x1B
        b>>=1
    return r
def gf_pow(base,exp):
    r=1
    while exp:
        if exp&1: r=gf_mul(r,base)
        base=gf_mul(base,base); exp>>=1
    return r

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

def gen_sbox(seed):
    sbox=list(range(256));xs=seed&0xFFFFFFFF
    for i in range(255,0,-1):
        xs^=(xs<<13)&0xFFFFFFFF;xs^=(xs>>17)&0xFFFFFFFF;xs^=(xs<<5)&0xFFFFFFFF
        j=xs%(i+1);sbox[i],sbox[j]=sbox[j],sbox[i]
    return sbox

CRC_T=[0x00000000,0x1DB71064,0x3B6E20C8,0x26D930AC,0x76DC4190,0x6B6B51F4,0x4DB26158,0x5005713C,
       0xEDB88320,0xF00F9344,0xD6D6A3E8,0xCB61B38C,0x9B64C2B0,0x86D3D2D4,0xA00AE278,0xBDBDF21C]
def crc16(data):
    c=0xFFFFFFFF
    for b in data[:16]: c^=b;c=((c>>4)^CRC_T[c&0xF])&0xFFFFFFFF;c=((c>>4)^CRC_T[c&0xF])&0xFFFFFFFF
    return c^0xFFFFFFFF

def full_verify(flag_bytes):
    """选手的 Python 正向验证"""
    mat=bytearray(128)
    mat[:96]=expand_py(flag_bytes)
    for i in range(16): mat[96+i]=mat[i]^SOKEY[i]
    for i in range(16): mat[112+i]=mat[32+i]
    rk=[struct.unpack_from('<I',mat,i*4)[0] for i in range(16)]
    cfgs=[]
    for i in range(16):
        b=mat[64+i];cfgs.append({'ss':(b>>0)&3,'sp':(b>>2)&3,'mm':(b>>4)&3,'nm':(b>>6)&3})
    seeds=[struct.unpack_from('<I',mat,80+i*4)[0] for i in range(4)]
    delta=struct.unpack_from('<I',mat,96)[0]
    chk=rk[15]^struct.unpack_from('<I',SOKEY,12)[0]
    diff=chk^EXPECTED_SOKEY_CHECK
    poison=(((diff|((~diff+1)&0xFFFFFFFF))>>31)&1)*0xDEADBEEF
    delta^=poison
    sboxes=[gen_sbox(s) for s in seeds]
    state=list(IV1);cm=0
    for rnd in range(16):
        if rnd==8: cm=crc16(bytes(state))
        dk=rk[rnd]
        if rnd>=8: dk^=struct.unpack_from('<I',bytes(state[:4]))[0]; dk^=cm
        sel=cfgs[rnd]['ss'] if rnd<8 else (cfgs[rnd]['ss']^state[0])&3
        state=[sboxes[sel][b] for b in state]
        tmp=state[:]
        for row in range(4):
            sv=SHIFTS[cfgs[rnd]['sp']][row]&3
            for col in range(4): state[row+4*col]=tmp[row+4*((col+sv)%4)]
        res=[0]*16
        for col in range(4):
            inp=state[col*4:col*4+4];m=MDS[cfgs[rnd]['mm']]
            for i in range(4):
                v=0
                for j in range(4): v^=gf_mul(m[i][j],inp[j])
                res[col*4+i]=v
        state=res
        p=NL_POWER[cfgs[rnd]['nm']&3];rc=(delta>>((rnd%4)*8))&0xFF
        state=[gf_pow(b^rc^(rnd&0xFF),p) for b in state]
        k=struct.pack('<I',dk)
        state=[state[i]^k[i%4] for i in range(16)]
    return bytes(state)

# 计算 target
target = full_verify(FLAG_B)
enc = bytes(target[i]^SOKEY[i] for i in range(16))
print(f"target_state = {target.hex()}")
print(f"ENC (for .so) = {enc.hex()}")
print()

# ═══ 选手策略: Z3 约束 ARX + soKey check (32-bit only) ═══
# 然后用 Python callback 验证每个候选解
print("=" * 60)
print("Strategy: Z3(ARX 12轮 + soKey_check 32-bit) + Python SPN verify")
print("=" * 60)

def z3_ror64(x,n): return LShR(x,n)|(x<<(64-n))
def z3_rol64(x,n): return (x<<n)|LShR(x,(64-n))

flag = [BitVec(f'f{i}',8) for i in range(25)]
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
material_z3=[]
for _ in range(3):
    for i in range(4):
        for j in range(8): material_z3.append(Extract(j*8+7,j*8,s[i]))
    s[0]=s[0]+s[2]; s[1]=s[1]^s[3]
    s[2]=z3_rol64(s[2],17); s[3]=z3_ror64(s[3],11)
material_z3 = material_z3[:96]

solver = Solver()
solver.set('timeout', 7200000)  # 2h

# 唯一约束: material[60:64] == EXPECTED_SOKEY_CHECK ^ soKey[12:16]
known_rk15 = EXPECTED_SOKEY_CHECK ^ struct.unpack_from('<I', SOKEY, 12)[0]
for i in range(4):
    solver.add(material_z3[60+i] == BitVecVal((known_rk15 >> (i*8)) & 0xFF, 8))

print(f"Constraint: material[60:64] == 0x{known_rk15:08x} (32-bit from soKey check)")
print(f"Solving + verifying loop (2h timeout)...")
print()

t0 = time.time()
attempts = 0
found = False

while True:
    elapsed = time.time() - t0
    if elapsed > 7200:
        print(f"Timeout after {attempts} attempts, {elapsed:.0f}s")
        break

    result = solver.check()
    if result != sat:
        print(f"Z3 returned {result} after {attempts} attempts, {elapsed:.1f}s")
        break

    m = solver.model()
    candidate = bytes([m.eval(flag[i]).as_long() for i in range(25)])
    attempts += 1

    # Python 正向验证
    state = full_verify(candidate)
    if state == target:
        found = True
        print(f"FOUND after {attempts} attempts, {elapsed:.1f}s!")
        print(f"Flag: {candidate.hex()}")
        print(f"Match expected: {candidate == FLAG_B}")
        break

    # 排除当前解，让 Z3 找下一个
    solver.add(Or(*[flag[i] != BitVecVal(candidate[i], 8) for i in range(25)]))

    if attempts % 10 == 0:
        print(f"  Attempt {attempts}, elapsed {elapsed:.1f}s, last candidate: {candidate[:8].hex()}...")

# 输出结果
output = []
output.append(f"=== Contestant Realistic Strategy ===")
output.append(f"ARX rounds: 12")
output.append(f"Z3 constraint: material[60:64] only (32-bit)")
output.append(f"Verification: Python SPN forward sim")
output.append(f"Attempts: {attempts}")
output.append(f"Time: {time.time()-t0:.1f}s ({(time.time()-t0)/60:.1f} min)")
output.append(f"Found: {found}")
if found:
    output.append(f"Flag: {candidate.hex()}")

result_text = "\n".join(output)
print()
print(result_text)
with open("z3_result.txt", "w") as f:
    f.write(result_text)
print("\nWritten to z3_result.txt")
