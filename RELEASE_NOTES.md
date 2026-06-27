# 2026 KCTF Challenge - Release Notes

## Challenge Overview

**Platform**: Android ARM64 (API 29+)  
**Type**: Reverse Engineering + Constraint Solving  
**Difficulty**: Advanced  
**Flag Format**: 100-character hex string (50 bytes)

## Final Flag

```
017a00e3001b009401d2045600f8000c0041ebb7dd290b8e1463b9a579df37109e4bdec8c072ad3dde96070f42e4135837ad
```

**Verification Status**: ✅ Tested on Pixel 6 Pro (Android 15)

---

## Challenge Structure

### Input Processing
- 100 hex characters → 50 bytes
- Interleaved split: even bytes (25B) → Scheme A, odd bytes (25B) → Scheme B
- Both schemes must pass

### Scheme A: Explicit Repair Chain
- Control flow repair (4 branches via self-modifying logic)
- Parameterized computation with soKey-derived constants
- Basic block address extraction from .text section

### Scheme B: Implicit Repair + Cryptanalysis
- ARX key expansion (XTEA-like, 16 rounds)
- Dynamic round extension (8 static + 4-16 dynamic rounds)
- SPN cipher (16 rounds, 4 S-boxes, 96-byte key material)
- Oracle shellcode (XOR-encrypted, returns seeds[16] + material[0:16])
- Z3 constraint solving required

---

## Key Technical Features

### 1. Self-Modifying Code
- soKey derived from `.text` CRC32 → creates circular dependency
- Constants encrypted with soKey XOR → must converge iteratively
- `converge.py` implements fixed-point iteration (typically 3-6 rounds)

### 2. Anti-Analysis Measures

**Honeytraps (5 types)**:
- **Trap A**: Fake dev backdoors (`DEBUG_MAGIC`, environment variables)
- **Trap B**: Time anomaly detection (clock_gettime sampled every 4 ARX rounds)
- **Trap C**: Debugger detection (TracerPid from /proc/self/status)
- **Trap D**: Memory integrity (BRK scan in /proc/self/maps)
- **Trap E**: Emulator detection (HWCAP check via /proc/self/auxv)

**Obfuscation**:
- String encryption (system call names, file paths)
- Dynamic symbol resolution (dlsym)
- Junk instructions (unreachable branches with garbage bytes)
- MBA (Mixed Boolean-Arithmetic) for XOR operations

### 3. Oracle Mechanism
- Shellcode stored XOR-encrypted in .text section
- 3-share key derivation (MBA constants + expand_key_material CRC + soKey)
- mmap RWX execution with all checks performed via syscalls (SVC)
- Returns material for Z3 modeling (prevents pure dynamic extraction)

---

## Build Artifacts

### Debug APK
- Path: `app/build/outputs/apk/debug/app-debug.apk`
- CRC32(.text): `5390cc99`
- Signed with: Android debug keystore
- Symbols: Stripped with `llvm-strip --strip-unneeded`

### Build Requirements
- Android NDK 27.0.12077973
- Gradle 8.7
- CMake 3.22.1+
- Python 3.8+ (for converge.py)

---

## Solving Approach

### Phase 1: Static Analysis
1. Decompile APK → extract libkctf.so
2. Identify JNI entry: `Java_com_autorun_kctf_MainActivity_nativeProcessInput`
3. Locate .rodata constants (ENC_EXPECTED_STATE, IV, etc.)
4. Reverse engineer:
   - `deriveNativeKey()` (Java) → soKey computation
   - `verify_scheme_a()` → control flow repair logic
   - `verify_scheme_b()` → ARX + SPN structure

### Phase 2: Scheme A Solution
- Extract basic block addresses from .text (BB0, BB1, BB6, BB7)
- Compute soKey from .text CRC32
- Decrypt ENC_EXPECTED_STATE_A using soKey
- Build constraint system for STEP1-STEP4 operations
- Solve for flagA[25] (typically has multiple solutions)

### Phase 3: Oracle Reverse Engineering
- Locate oracle shellcode (search for mmap/mprotect syscall patterns)
- Extract 3-share key derivation logic
- Decrypt shellcode → disassemble → identify material return structure
- Run on device/emulator to obtain concrete seeds[16] + material[0:16]

### Phase 4: Scheme B Z3 Modeling
- Model ARX key expansion (16 XTEA rounds)
- Model dynamic round extension (time-based, Unicorn-based)
- Model SPN cipher (16 rounds, custom S-boxes generated from seeds)
- Add oracle constraints (seeds, material[0:16])
- Add final state constraints (ENC_EXPECTED_STATE, ENC_EXPECTED_STATE2)
- Solve for flagB[25] (typically 10-30 hours on modern CPU)

### Phase 5: Flag Assembly
- Interleave flagA and flagB → 50-byte result
- Convert to 100-character hex string
- Submit to APK for verification

---

## Known Issues & Limitations

### const_xor Disabled
- **Reason**: Self-referential CRC caused SIGSEGV on some devices
- **Impact**: .rodata constants stored in plaintext (easier static analysis)
- **Mitigation**: Core difficulty remains in ARX/SPN modeling, not constant extraction

### Convergence Instability (Release Build)
- **Symptom**: `-O2` optimization causes .text layout oscillation
- **Workaround**: Use debug build (`assembleDebug`) which converges reliably
- **Root Cause**: Compiler reordering changes basic block addresses unpredictably

### Oracle Device Dependency
- **Issue**: Shellcode requires real ARM64 CPU (syscalls, privilege checks)
- **Workaround**: Use Android emulator with KVM acceleration or real device
- **Alternative**: Reverse engineer shellcode statically (harder but possible)

---

## Testing Checklist

- [x] Python simulation (converge.py + verify.py) all PASS
- [x] APK builds successfully (debug mode)
- [x] .text CRC converges within 6 iterations
- [x] Correct flag accepted on real device (Pixel 6 Pro, Android 15)
- [x] Wrong flags rejected (tested 10+ variations)
- [x] Oracle shellcode executes without crashes
- [x] All honeytraps trigger correctly (manual verification)

---

## File Inventory

### Source Code
- `app/src/main/cpp/src/`: Native implementation (14 .c files, 1 .S file)
- `app/src/main/java/`: Java/Kotlin UI + JNI bridge
- `app/CMakeLists.txt`: Build configuration

### Documentation
- `SOLUTION.md`: Complete writeup with technical details
- `WRITEUP_IDEAL.md`: Ideal solving path for contestants
- `2026KCTF_v4.md`: Original design specification
- `2026KCTF_CFG.md`: Control flow graph documentation

### Tools
- `converge.py`: Iterative constant convergence automation
- `verify.py`: Python simulation for verification
- `keygen.py`: Flag generation (deprecated after convergence)

### Test Scripts
- `test_z3_full_spn.py`: Z3 solver for Scheme B
- `test_keygen_scheme_a.py`: Scheme A constraint solver

---

## Credits

**Challenge Design**: autorun14514  
**Testing Platform**: Pixel 6 Pro (Android 15)  
**Development Tools**: Claude Code (Anthropic Opus 4.8)

---

## Release Information

**Version**: 1.0.0  
**Release Date**: 2026-06-07  
**Status**: Production Ready ✅

For support or questions, refer to SOLUTION.md or WRITEUP_IDEAL.md.
