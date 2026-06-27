#!/usr/bin/env python3
"""
test_keygen_scheme_a.py - Test keygen.py Scheme A constraint solving.

Verifies: given correct KCT/KOUT values, Z3 can independently solve for
LCG seed and step2/step3 parameters.
"""
import struct, sys, time
sys.path.insert(0, '.')

from keygen import (
    _compute_sbox_from_seed, _xtea_check_encrypt,
    _solve_lcg_seed, _solve_step2_step3,
    expand_key_material
)
import keygen

print("=" * 64)
print("  Test: keygen.py Scheme A constraint solving")
print("=" * 64)
print()

# Known correct parameters
BB0_BRANCH_OFF = 0x2284
BB1_OFF        = 0x228c
BB6_ADR_OFF    = 0x277c
BB7_ENTRY_OFF  = 0x2784
soKey = bytes.fromhex("2e4bbe730e45bbe0e5afe89317e2a336")

XTEA_DELTA = 0x9E3779B9
LCG_SEED   = 0xDEADC0DE
STEP2_AMT  = 7
STEP3_RAW  = 0x42 | (0x13 << 8) | (0x37 << 16)

# Compute flag[9:13]
imm21 = BB7_ENTRY_OFF - BB6_ADR_OFF
adr_bits = ((imm21 & 0x3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5)
sokey_0_3 = struct.unpack_from("<I", soKey, 0)[0]
flag_9_12 = (sokey_0_3 ^ adr_bits) & 0xFFFFFFFF

# Compute sbox
cfg_dep = BB6_ADR_OFF & 0xFF
sbox = _compute_sbox_from_seed(flag_9_12, cfg_dep)
sbox_first = sbox[0]
print(f"[*] flag[9:13]=0x{flag_9_12:08x} cfg_dep=0x{cfg_dep:02x} sbox[0]=0x{sbox_first:02x}")

# Compute round_constants (forward)
lcg_v = (LCG_SEED ^ (sbox_first * 0x01010101)) & 0xFFFFFFFF
rc = []
for _ in range(32):
    lcg_v = (lcg_v * 1664525 + 1013904223) & 0xFFFFFFFF
    rc.append(lcg_v)

# Compute KCT (ground truth)
KPT_vals = [(0x00000001, 0x00000002),
            (0xDEADBEEF, 0xCAFEBABE),
            (0x12345678, 0x9ABCDEF0)]
KCT_computed = [_xtea_check_encrypt(a, b, XTEA_DELTA, rc) for a, b in KPT_vals]
print(f"[*] KCT[0] = (0x{KCT_computed[0][0]:08x}, 0x{KCT_computed[0][1]:08x})")

# Compute KOUT (ground truth)
rc_high4 = (rc[0] >> 28) & 0xF
step3_bits = 16 + rc_high4
mask = (1 << step3_bits) - 1 if step3_bits < 32 else 0xFFFFFFFF
step3_param = STEP3_RAW & mask

def s3(val, param, bits=step3_bits):
    m = (1 << bits) - 1 if bits < 32 else 0xFFFFFFFF
    param &= m
    return (val ^ (((val >> 5) + param) & 0xFFFFFFFF) ^
            (((val << 4) + (param >> 12)) & 0xFFFFFFFF)) & 0xFFFFFFFF

def s2(val, amt):
    amt &= 0x1F
    if amt == 0: return val
    return ((val << amt) | (val >> (32 - amt))) & 0xFFFFFFFF

KIN_vals = [0x00000001, 0x12345678, 0xdeadbeef, 0xcafebabe,
            0x8badf00d, 0xfeedface, 0x01234567, 0x89abcdef]
KOUT_computed = [s2(s3(x, step3_param), STEP2_AMT) for x in KIN_vals]
print(f"[*] KOUT[0] = 0x{KOUT_computed[0]:08x}, step3_bits={step3_bits}")

# Set keygen module's constraint constants to ground truth
keygen.KPT = KPT_vals
keygen.KCT = KCT_computed
keygen.KIN = KIN_vals
keygen.KOUT = KOUT_computed

# ---- Test 1: Z3 solve LCG seed ----
print("\n[*] Test 1: Z3 solve LCG seed...")
t0 = time.time()
solved_seed = _solve_lcg_seed(sbox_first, XTEA_DELTA)
t1 = time.time()

if solved_seed is None:
    print(f"[FAIL] Z3 returned UNSAT ({t1-t0:.1f}s)")
    sys.exit(1)

# Verify solution produces correct KCT
lcg_check = (solved_seed ^ (sbox_first * 0x01010101)) & 0xFFFFFFFF
rc_check = []
for _ in range(32):
    lcg_check = (lcg_check * 1664525 + 1013904223) & 0xFFFFFFFF
    rc_check.append(lcg_check)
all_kct_ok = True
for i in range(3):
    o0, o1 = _xtea_check_encrypt(KPT_vals[i][0], KPT_vals[i][1], XTEA_DELTA, rc_check)
    if o0 != KCT_computed[i][0] or o1 != KCT_computed[i][1]:
        all_kct_ok = False
        break

if all_kct_ok:
    print(f"[PASS] LCG seed = 0x{solved_seed:08x} ({t1-t0:.1f}s)")
else:
    print(f"[FAIL] LCG seed = 0x{solved_seed:08x} doesn't produce correct KCT ({t1-t0:.1f}s)")
    sys.exit(1)

# Use solved rc for step2/step3 test
rc = rc_check

# ---- Test 2: Z3 solve step2/step3 ----
print("\n[*] Test 2: Z3 solve step2_amount + step3_param...")
t0 = time.time()
solved_amt, solved_raw = _solve_step2_step3(rc[0], XTEA_DELTA)
t1 = time.time()

if solved_amt is None:
    print(f"[FAIL] Z3 returned UNSAT ({t1-t0:.1f}s)")
    sys.exit(1)

# Verify solution against KIN/KOUT
alt_bits = 16 + ((rc[0] >> 28) & 0xF)
alt_mask = (1 << alt_bits) - 1 if alt_bits < 32 else 0xFFFFFFFF
alt_param = solved_raw & alt_mask
all_ok = True
for i in range(8):
    v = s2(s3(KIN_vals[i], alt_param, alt_bits), solved_amt)
    if v != KOUT_computed[i]:
        all_ok = False
        break

if all_ok:
    print(f"[PASS] step2={solved_amt}, raw=0x{solved_raw:06x} ({t1-t0:.1f}s)")
else:
    print(f"[FAIL] step2={solved_amt}, raw=0x{solved_raw:06x} KIN/KOUT mismatch ({t1-t0:.1f}s)")
    sys.exit(1)

print("\n[autoctf] ALL TESTS PASSED")
