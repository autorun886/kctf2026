# KCTF2026 Current Obfuscation Summary

This document records the current internal anti-reversing and anti-AI design after the latest hardening pass. It is an internal maintenance document, not contestant-facing material.

## Overall Assessment

The current encryption and obfuscation state is generally healthy for a CTF reverse-engineering challenge:

- Release `libkctf.so` is stripped. The dynamic symbol table only exposes the JNI entry and libc dependencies.
- Release `classes.dex` no longer contains the key Java literals used for `soKey` recovery, such as ABI names, `libkctf.so`, `.kctfguard`, or `.text`.
- Native semantic names such as `repair_*`, `verify_scheme_*`, and `oracle` do not appear in the release APK string scan.
- The final check is no longer a single compare or a single solver target. It combines Scheme A repair state, Scheme B material, oracle output, APK-bound `soKey`, runtime integrity checks, and expected-state masks.
- Correct-path constraints remain reproducible by `converge.py`, so the challenge remains buildable and solvable.

The design is strongest against automated static summarization and simple dynamic hook workflows. A strong human reverser can still solve it by reconstructing the dataflow, which is the intended balance.

## Current Verification Values

Current release values after convergence:

```text
guard_crc32 = 3e0695ce
soKey       = 870573e5f5c63d52862dbd05ab3d9494
flagA       = a77a78ffc894367d1bf5bb3faab6e2f4db0070533de8b73443
flagA_dec   = 0200000001832dbd05c70573e5b979379edec0adde07421337
flagB       = 7ae31b94d256f80c41b7298e63a5df104bc8723d960fe458ad
flag        = a77a7ae3781bff94c8d2945636f87d0c1b41f5b7bb293f8eaa63b6a5e2dff410db4b00c87072533d3d96e80fb7e4345843ad
```

`flagA` is the externally submitted encoded half. `flagA_dec` is the internal decoded 25-byte Scheme A repair material.

## Java Layer

The short-named Java metadata helper still returns the native-facing blob:

```text
maskedKeyShare[16] || crc32[4] || textOff[4] || textSize[4] || profileHint[4]
```

Hardening currently applied:

- Key strings are stored as encrypted integer arrays, not Java string constants.
- Decryption is delayed and implemented through a small switch-based state machine.
- The metadata helper itself is control-flow flattened with a switch state machine.
- ABI names, APK library path fragments, `.kctfguard`, and `.text` are reconstructed at runtime.
- Release dex scan shows no key Java literals for the `soKey` path. The old semantic method name is gone; native decodes the reflection method/signature tokens at runtime.

Current release `classes.dex` scan only shows unrelated Android strings and the JNI entry name; it does not show `deriveNativeKey`, `libkctf`, ABI names, `.kctfguard`, or `.text`.

## APK-Bound soKey

`soKey` is derived from a stable executable guard region inside `libkctf.so`:

1. Java reads the library from the APK.
2. It locates `.kctfguard`, or falls back to scanning `.text` for the guard byte pattern.
3. It computes CRC32 and expands it into 16 bytes with an LCG-style expansion.
4. Native receives the masked share and runtime metadata.
5. Native recomputes loaded text/guard integrity and poisons the key if APK and memory disagree.

This binds the valid input to the released APK and makes repacking or patching affect final verification rather than producing an obvious early failure.

## Scheme A

Scheme A is a repair-chain design:

```text
encoded flagA -> decode_flag_a -> repair_cfg -> repair_sbox -> repair_constants -> repair_semantics -> core_compute -> expected compare
```

Current hardening:

- Submitted `flagA` is not the raw repair material. It is decoded with a reversible permutation/XOR/add/rotate layer depending on `soKey`.
- The decoded layout still remains solvable and stable:
  - CFG repair fields
  - S-box xorshift seed
  - XTEA-like delta
  - LCG seed
  - step2/step3 semantic parameters
- `repair_cfg` validates basic block offsets and sets `dispatch_table[0]` for later S-box repair.
- `repair_sbox` reconstructs `sbox_shipped` from the decoded seed and CFG-dependent offset.
- `repair_constants` reconstructs `xtea_delta` and `round_constants`; timing anomalies silently poison the result.
- `repair_semantics` reconstructs `step2_amount`, `step3_bits`, and `step3_param`; BRK detection silently clears the effective state.
- `core_compute` runs a modified XTEA/Feistel-like computation over two 32-bit pairs and mixes the repaired S-box.

Scheme A produces `a_share`, an 8-bit derived share from repaired Scheme A state. This share feeds Scheme B oracle tags and expected-state masks.

## Scheme B

Scheme B remains the main solver-heavy half:

```text
flagB -> expand_key_material -> key_schedule -> oracle checks -> SPN(IV1) + SPN(IV2)
```

Current hardening:

- `flagB` expands through ARX material generation.
- Key schedule derives round keys, S-box configs, dynamic seeds, and delta.
- Two different IVs are verified to keep the solution unique enough for the challenge.
- SPN rounds include S-box selection, row shifts, MDS matrix mixing, nonlinear GF powers, dynamic round keys, and state-dependent behavior in later rounds.
- Wrong `soKey` does not simply fail early; it poisons delta/key state.

Scheme B consumes `a_share`, so it is no longer fully independent from Scheme A.

## A/B Coupling

The challenge now has bidirectional low-dimensional coupling:

- Scheme A expected state is masked with a share derived from Scheme B material.
- Scheme B expected states are masked with Scheme A share.
- Oracle tag calculation includes Scheme A share.
- Oracle material-head encoding also includes Scheme A share, `soKey`, and seeds.

This is intentionally low-dimensional. It raises dataflow reconstruction cost without making the problem an opaque unsolvable black box.

## Expected-State Obfuscation

The three final expected states are no longer stored as one contiguous encrypted 16-byte array.

Current structure:

```text
ENC_EXPECTED_STATE_S0  + ENC_EXPECTED_STATE_S1
ENC_EXPECTED_STATE2_S0 + ENC_EXPECTED_STATE2_S1
ENC_EXPECTED_STATE_A_S0 + ENC_EXPECTED_STATE_A_S1
```

Runtime flow:

```text
shards -> const_xor_load_split -> const_xor_load -> soKey xor -> cross mask -> compare
```

The split stage uses lane rotation, per-domain constants, and MBA-flavored byte operations before the original `const_xor` layer. This reduces the value of searching for a single target-state array in `.rodata`.

## Oracle Shellcode

Oracle is still executed as runtime-decrypted shellcode:

1. C computes a 4-share XOR key.
2. The shellcode bytes are XOR decrypted into an anonymous mmap region.
3. The region is switched RX with `mprotect`.
4. Shellcode performs anti-debug and anti-hook checks.
5. It returns 32 bytes into native memory.
6. The mmap region and key material are wiped after execution.

Current returned data layout:

```text
seeds[16] || encoded_material_head[8] || tag[8]
```

The raw `material[0:8]` is no longer returned. It is encoded as:

```text
encoded_material_head = f(material[0:8], seeds[16], soKey, a_share)
```

This preserves an 8-byte material constraint but removes a direct plaintext oracle window.

## Oracle Anti-Hook and Environment Coupling

The oracle key is derived from four shares, including environment-derived state:

- static/rodata shares
- `soKey` share refreshed before each call
- environment share derived from clean runtime conditions

Environment and hook checks include:

- `TracerPid` status checks
- `/proc/self/maps` scan for instrumentation artifacts
- HWCAP checks
- inline hook detection on selected libc functions
- shellcode-level inspection of the first few `mmap` instructions for ARM64 jump stubs

Failures are generally turned into wrong key material or poisoned checks rather than clean fatal errors.

## Decoys and Honey Paths

Current decoys are not purely dead code:

- `fake_material_decoy` is gated by a runtime mask derived from oracle/SPN/seed/tag cleanliness.
- Correct path keeps the fake constraint masked off.
- Wrong, hooked, or polluted paths can activate the fake material constraint.
- Several functions and constants still resemble familiar crypto building blocks, but correct analysis must follow dataflow rather than names.

This helps against AI or scripts that delete anything resembling anti-debug logic without checking whether it repairs or poisons computation.

## MBA and Nonlinear Obfuscation

Current MBA/nonlinear layers include:

- MDS/inverse-MDS identities for XOR-like expressions.
- Feistel/inverse-Feistel wrappers around arithmetic identities.
- ANF-style byte identity wrappers.
- GF multiplication and GF exponentiation in SPN nonlinear layers.
- Matrix mixing in SPN and expected/material encoding.

The MBA usage is intentionally not the only source of hardness. It is used to obscure local expressions, while the main challenge remains dataflow reconstruction and constraint modeling.

## Release Artifact Checks

Current release checks performed:

```text
./gradlew assembleDebug
python3 converge.py --release --max-iter 10
python3 verify.py app/build/intermediates/stripped_native_libs/release/stripReleaseDebugSymbols/out/lib/arm64-v8a/libkctf.so
python3 flag_generate.py app/build/outputs/apk/release/app-release.apk
```

Observed status:

- Debug build passes.
- Release convergence passes with `ALL PASS`.
- Scheme A correct/wrong checks pass.
- Scheme B IV1/IV2/wrong flag/wrong soKey checks pass.
- `verify.py` and `flag_generate.py` agree on the current flag.
- Dynamic symbol table is clean except for JNI entry and libc dependencies.
- Release dex has no direct Java `soKey` path literals.

## Current Weak Points

Remaining weaknesses are acceptable for a solvable challenge:

- Source-level names and comments are still descriptive. This is fine if source is not distributed; it should be scrubbed for any public source release.
- The Java metadata helper remains recoverable by dataflow, but no longer advertises itself through the old semantic method name.
- A/B coupling is still low-dimensional by design. Increasing it too much would make the problem less teachable and harder to validate.
- APK-level strings still naturally include ZIP entries and ELF section names. This is normal and separate from Java constant-pool leakage.
- `converge.py` is authoritative. Helper scripts with embedded BB offsets must be kept in sync after native layout changes.

## Maintenance Rules

When changing native code:

1. Run debug build first.
2. Run release convergence.
3. Confirm `ALL PASS`.
4. Sync helper BB offsets if `core_compute` offsets changed.
5. Run `verify.py` and `flag_generate.py`.
6. Re-scan release dex for Java string leakage if `MainActivity.java` changes.

Commands:

```bash
./gradlew assembleDebug
python3 converge.py --release --max-iter 10
python3 verify.py app/build/intermediates/stripped_native_libs/release/stripReleaseDebugSymbols/out/lib/arm64-v8a/libkctf.so
python3 flag_generate.py app/build/outputs/apk/release/app-release.apk
unzip -q -o app/build/outputs/apk/release/app-release.apk classes.dex -d /tmp/kctf-dex-check
strings -a /tmp/kctf-dex-check/classes.dex | rg "libkctf|arm64-v8a|armeabi-v7a|x86_64|\.kctfguard|\.text"
```

## Recommendation

The current state is close to the practical upper bound for this challenge without harming solvability. Further hardening should focus on small presentation and artifact cleanup rather than adding new high-entropy couplings.

Recommended next steps only if needed:

- Update or separate public-facing docs from internal docs.
- Avoid distributing `converge.py`, `verify.py`, and generated helper scripts with secrets.
- Keep source comments if this remains private; strip or rename them before any source release.
