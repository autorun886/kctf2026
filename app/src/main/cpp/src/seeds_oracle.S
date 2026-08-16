/*
 * seeds_oracle.S — ARM64 shellcode (position-independent)
 *
 * 功能：反 frida / 反调试 / 反模拟执行，通过后返回 sbox_seeds[4]
 * 所有系统调用均使用 SVC 指令，绕过 PLT/GOT hook。
 *
 * 调用约定：
 *   x0 = 输出 buffer 指针 (uint8_t[32])
 *   x1 = oracle_ctx 指针，ctx[0] 为 libc mmap 地址
 *   返回 x0 = 0 成功, 不返回（exit_group）= 检测到异常
 *
 * 此文件被放入 .rodata，运行时 mmap RWX 后执行。
 */

    .section .rodata, "a", %progbits
    .balign 16
    .globl oracle_code_start
    .globl oracle_code_end
    .hidden oracle_code_start
    .hidden oracle_code_end

oracle_code_start:

/* ═══════════════════════════════════════════════════════
 * Prologue
 * ═══════════════════════════════════════════════════════ */
    stp     x29, x30, [sp, #-160]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #112]
    mov     w25, #0                    // anti-check error accumulator
    str     x0, [sp, #64]              // 保存输出指针
    str     x1, [sp, #72]              // 保存 oracle_ctx 指针

/* ═══════════════════════════════════════════════════════
 * Check 0: Inline Hook — 检查 libc mmap 入口是否被跳板覆盖
 * C 层传入 dlsym("mmap") 地址，shellcode 自己读取前 4 条指令：
 *   - B/BL immediate
 *   - LDR literal 后紧跟 BR/BLR register
 * 命中说明 mmap 很可能被 Frida/Xposed inline hook。
 * ═══════════════════════════════════════════════════════ */
    ldr     x19, [sp, #72]             // ctx
    cbz     x19, .L_check1
    ldr     x19, [x19]                 // ctx->mmap_addr
    cbz     x19, .L_check1

    mov     w24, #4                    // 只检查入口前 4 条，降低 libc veneer 误报
    mov     w21, #0                    // prev_was_ldr_literal

.L_mmap_hook_scan:
    cbz     w24, .L_check1
    ldr     w20, [x19], #4

    /* B/BL immediate: (insn & 0x7c000000) == 0x14000000 */
    movz    w22, #0x7c00, lsl #16
    and     w23, w20, w22
    movz    w22, #0x1400, lsl #16
    cmp     w23, w22
    b.eq    .L_mmap_hook_bad

    /* 如果上一条是 LDR literal，本条是 BR/BLR register，则视为跳板 */
    cbz     w21, .L_mmap_check_ldr
    movz    w22, #0xfc1f
    movk    w22, #0xffff, lsl #16      // 0xfffffc1f
    and     w23, w20, w22
    movz    w22, #0x0000
    movk    w22, #0xd61f, lsl #16      // BR register family
    cmp     w23, w22
    b.eq    .L_mmap_hook_bad
    movz    w22, #0x0000
    movk    w22, #0xd63f, lsl #16      // BLR register family
    cmp     w23, w22
    b.eq    .L_mmap_hook_bad
    b       .L_mmap_check_ldr

.L_mmap_hook_bad:
    movz    w22, #0xC503
    movk    w22, #0xB701, lsl #16
    eor     w25, w25, w22
    b       .L_check1

.L_mmap_check_ldr:
    /* LDR literal: (insn & 0xff000000) == 0x58000000 */
    movz    w22, #0xff00, lsl #16
    and     w23, w20, w22
    movz    w22, #0x5800, lsl #16
    cmp     w23, w22
    cset    w21, eq
    sub     w24, w24, #1
    b       .L_mmap_hook_scan

/* ═══════════════════════════════════════════════════════
 * Check 1: Anti-Debug — TracerPid via /proc/self/status
 * SVC openat + read + close, 解析 TracerPid
 * ═══════════════════════════════════════════════════════ */
.L_check1:

    /* 在栈上构造 "/proc/self/status\0" (18 bytes)
     * 用立即数构造，避免明文字符串 */
    /* "/proc/se" = 0x65732f636f72702f (LE) */
    mov     x19, #0x702f
    movk    x19, #0x6f72, lsl #16
    movk    x19, #0x2f63, lsl #32
    movk    x19, #0x6573, lsl #48
    str     x19, [sp, #80]

    /* "lf/statu" = 0x757461742f666c (LE, 7 bytes padded) */
    /* Actually: "lf/statu" as 8 bytes = 6c 66 2f 73 74 61 74 75 */
    mov     x20, #0x666c
    movk    x20, #0x732f, lsl #16
    movk    x20, #0x6174, lsl #32
    movk    x20, #0x7574, lsl #48
    str     x20, [sp, #88]

    /* "s\0" = 0x0073 */
    mov     w21, #0x0073
    strh    w21, [sp, #96]

    /* SVC openat(AT_FDCWD=-100, path, O_RDONLY=0) */
    mov     x0, #-100                  // AT_FDCWD
    add     x1, sp, #80               // path ptr
    mov     x2, #0                     // O_RDONLY
    mov     x3, #0
    mov     x8, #56                    // __NR_openat
    svc     #0

    /* open 失败则跳过此检测 */
    cmp     x0, #0
    b.lt    .L_check2

    mov     x19, x0                    // fd

    /* SVC read(fd, buf, 512) — 用 sp+100 开始的区域做 buffer */
    /* 注意：我们的栈帧 160 字节不够放 512，向下扩展 */
    sub     sp, sp, #528
    mov     x0, x19
    mov     x1, sp                     // buf at sp
    mov     x2, #527
    mov     x8, #63                    // __NR_read
    svc     #0

    mov     x20, x0                    // bytes_read
    mov     x21, sp                    // buf_start

    /* SVC close(fd) */
    mov     x0, x19
    mov     x8, #57                    // __NR_close
    svc     #0

    /* 解析 TracerPid: 搜索 "TracerPid:\t" 然后读数字 */
    /* 搜索模式: 'T'=0x54 'r'=0x72 'a'=0x61 'c'=0x63 'e'=0x65 'r'=0x72 'P'=0x50 */
    cmp     x20, #20
    b.lt    .L_status_done

    mov     x22, x21                   // scan ptr
    add     x23, x21, x20
    sub     x23, x23, #12             // stop before end

.L_scan_tracer:
    cmp     x22, x23
    b.ge    .L_status_done

    ldrb    w0, [x22]
    cmp     w0, #0x54                  // 'T'
    b.ne    .L_scan_next
    ldrb    w0, [x22, #1]
    cmp     w0, #0x72                  // 'r'
    b.ne    .L_scan_next
    ldrb    w0, [x22, #5]
    cmp     w0, #0x72                  // 'r' (TracerPid 第6字符)
    b.ne    .L_scan_next
    ldrb    w0, [x22, #6]
    cmp     w0, #0x50                  // 'P'
    b.ne    .L_scan_next

    /* 找到 "TracerP", 跳到 ':' 后面 */
    add     x22, x22, #10             // skip "TracerPid:"
.L_skip_ws:
    ldrb    w0, [x22]
    cmp     w0, #0x20                  // ' '
    b.eq    .L_ws_next
    cmp     w0, #0x09                  // '\t'
    b.ne    .L_parse_num
.L_ws_next:
    add     x22, x22, #1
    b       .L_skip_ws

.L_parse_num:
    mov     w24, #0                    // result = 0
.L_digit:
    ldrb    w0, [x22]
    sub     w1, w0, #0x30             // w1 = ch - '0'
    cmp     w1, #9
    b.hi    .L_check_pid
    mov     w2, #10
    mul     w24, w24, w2
    add     w24, w24, w1
    add     x22, x22, #1
    b       .L_digit

.L_check_pid:
    /* TracerPid != 0 时不直接退出，改为污染后续 oracle 数据解码 */
    cbz     w24, .L_status_done
    movz    w0, #0xB00D
    movk    w0, #0x713C, lsl #16
    eor     w25, w25, w0
    b       .L_status_done

.L_scan_next:
    add     x22, x22, #1
    b       .L_scan_tracer

.L_status_done:
    /* 恢复栈（回收 528 字节 read buffer） */
    add     sp, sp, #528

/* ═══════════════════════════════════════════════════════
 * Check 2: Anti-Frida — /proc/self/maps 扫描 "frida"/"xposed"
 * ═══════════════════════════════════════════════════════ */
.L_check2:
    /* 构造 "/proc/self/maps\0" (16 bytes) on stack */
    /* "/proc/se" 已经在 [sp+80] — 重新构造（栈可能被 read 覆盖） */
    mov     x19, #0x702f
    movk    x19, #0x6f72, lsl #16
    movk    x19, #0x2f63, lsl #32
    movk    x19, #0x6573, lsl #48
    str     x19, [sp, #80]

    /* "lf/maps\0" = 6c 66 2f 6d 61 70 73 00 */
    mov     x20, #0x666c
    movk    x20, #0x6d2f, lsl #16
    movk    x20, #0x7061, lsl #32
    movk    x20, #0x0073, lsl #48
    str     x20, [sp, #88]

    /* SVC openat */
    mov     x0, #-100
    add     x1, sp, #80
    mov     x2, #0
    mov     x3, #0
    mov     x8, #56
    svc     #0

    cmp     x0, #0
    b.lt    .L_check3

    mov     x19, x0                    // fd

    /* 循环读取 maps，每次 512 字节扫描 "frid"/"xpos" */
    mov     w22, #0                    // suspicious count

.L_maps_read_loop:
    sub     sp, sp, #528
    mov     x0, x19
    mov     x1, sp
    mov     x2, #527
    mov     x8, #63                    // __NR_read
    svc     #0

    cmp     x0, #4
    b.lt    .L_maps_read_done

    mov     x20, x0                    // bytes_read
    mov     x21, sp                    // buf
    add     x23, x21, x20
    sub     x23, x23, #4              // stop 4 bytes before end

.L_maps_scan:
    cmp     x21, x23
    b.ge    .L_maps_chunk_done

    /* 检测 "frid" = 66 72 69 64 */
    ldr     w0, [x21]
    movz    w1, #0x7266               // "frid" LE low16
    movk    w1, #0x6469, lsl #16      // "frid" LE high16
    cmp     w0, w1
    b.eq    .L_maps_found

    /* 检测 "xpos" = 78 70 6f 73 */
    movz    w1, #0x7078               // "xpos" LE low16
    movk    w1, #0x736f, lsl #16      // "xpos" LE high16
    cmp     w0, w1
    b.eq    .L_maps_found

    add     x21, x21, #1
    b       .L_maps_scan

.L_maps_found:
    add     w22, w22, #1
    add     x21, x21, #4
    b       .L_maps_scan

.L_maps_chunk_done:
    add     sp, sp, #528
    /* 如果已经发现 suspicious，不用继续读 */
    cbnz    w22, .L_maps_close
    b       .L_maps_read_loop

.L_maps_read_done:
    add     sp, sp, #528

.L_maps_close:
    mov     x0, x19
    mov     x8, #57                    // __NR_close
    svc     #0

    /* 发现 frida/xposed 时累计误差，后续表现为数据变换误差 */
    cbz     w22, .L_check3
    movz    w0, #0xF12A
    movk    w0, #0xD41D, lsl #16
    eor     w25, w25, w0

/* ═══════════════════════════════════════════════════════
 * Check 3: Anti-Emulation — /proc/self/auxv HWCAP 检测
 * 真机 ARM64: AT_HWCAP (type=16) 至少含 HWCAP_FP|HWCAP_ASIMD = 0x3
 * Unicorn/QEMU user 可能返回 0 或缺失
 * ═══════════════════════════════════════════════════════ */
.L_check3:
    /* 构造 "/proc/self/auxv\0" (16 bytes) */
    /* "/proc/se" 复用 */
    mov     x19, #0x702f
    movk    x19, #0x6f72, lsl #16
    movk    x19, #0x2f63, lsl #32
    movk    x19, #0x6573, lsl #48
    str     x19, [sp, #80]

    /* "lf/auxv\0" = 6c 66 2f 61 75 78 76 00 */
    mov     x20, #0x666c
    movk    x20, #0x612f, lsl #16
    movk    x20, #0x7875, lsl #32
    movk    x20, #0x0076, lsl #48
    str     x20, [sp, #88]

    mov     x0, #-100
    add     x1, sp, #80
    mov     x2, #0
    mov     x3, #0
    mov     x8, #56
    svc     #0

    cmp     x0, #0
    b.lt    .L_checks_passed           // 打不开就跳过

    mov     x19, x0

    /* 读取 auxv（每条目 16 字节：8 byte type + 8 byte value） */
    sub     sp, sp, #528
    mov     x0, x19
    mov     x1, sp
    mov     x2, #512
    mov     x8, #63
    svc     #0

    mov     x20, x0                    // bytes_read

    mov     x0, x19
    mov     x8, #57                    // close
    svc     #0

    /* 扫描 auxv 找 AT_HWCAP (type=16) */
    mov     x21, sp
    add     x23, x21, x20
    mov     w22, #0                    // found_hwcap = 0

.L_auxv_scan:
    add     x24, x21, #16
    cmp     x24, x23
    b.gt    .L_auxv_done

    ldr     x0, [x21]                 // type
    ldr     x1, [x21, #8]             // value

    /* AT_NULL = 0 → 结束 */
    cbz     x0, .L_auxv_done

    /* AT_HWCAP = 16 */
    cmp     x0, #16
    b.ne    .L_auxv_next

    /* 检查 HWCAP_FP | HWCAP_ASIMD (bit 0,1) */
    and     x1, x1, #0x3
    cmp     x1, #0x3
    b.eq    .L_hwcap_ok
    /* HWCAP 缺少基本能力 → 模拟器；不直接退出，污染 oracle 解码 */
    add     sp, sp, #528
    movz    w0, #0xA11D
    movk    w0, #0x4863, lsl #16
    eor     w25, w25, w0
    b       .L_checks_passed

.L_hwcap_ok:
    mov     w22, #1
.L_auxv_next:
    add     x21, x21, #16
    b       .L_auxv_scan

.L_auxv_done:
    add     sp, sp, #528
    /* 如果完全没找到 AT_HWCAP → 可疑但不致命，跳过 */

/* ═══════════════════════════════════════════════════════
 * All checks passed — 返回 seeds[16] + encoded material[0:8] + tag[8]
 * Payload is stored as a permuted 32-byte share plus a 16-byte decode table.
 * 不暴露 material[8:16]，避免直接补齐 ARX 末态。
 * ═══════════════════════════════════════════════════════ */
.L_checks_passed:
    ldr     x0, [sp, #64]             // 输出指针
    adr     x1, .L_oracle_data
    mov     w2, #0

.L_oracle_decode_loop:
    mov     w3, w2
    mov     w4, #5
    mul     w3, w3, w4
    add     w3, w3, #11
    and     w3, w3, #31
    ldrb    w5, [x1, w3, uxtw]

    mov     w4, #7
    mul     w3, w2, w4
    add     w3, w3, #5
    and     w3, w3, #15
    add     w3, w3, #32
    ldrb    w6, [x1, w3, uxtw]

    mov     w4, #11
    mul     w3, w2, w4
    add     w3, w3, #9
    and     w3, w3, #15
    add     w3, w3, #32
    ldrb    w7, [x1, w3, uxtw]

    and     w8, w2, #7
    add     w8, w8, #1
    lsl     w9, w7, w8
    mov     w10, #8
    sub     w10, w10, w8
    lsr     w7, w7, w10
    orr     w7, w7, w9
    and     w7, w7, #0xFF

    eor     w5, w5, w6
    eor     w5, w5, w7

    mov     w6, #0x3D
    mul     w6, w2, w6
    add     w6, w6, #0xA7
    eor     w6, w6, w2, lsl #1
    eor     w5, w5, w6

    /* w25 为 0 时恒等；检测异常时表现为返回常量的隐蔽数据误差 */
    eor     w7, w25, w25, lsr #11
    eor     w7, w7, w25, lsr #21
    and     w7, w7, #0xFF
    add     w8, w2, #1
    mul     w7, w7, w8
    eor     w7, w7, w7, lsr #4
    eor     w5, w5, w7

    strb    w5, [x0, w2, uxtw]
    add     w2, w2, #1
    cmp     w2, #32
    b.lt    .L_oracle_decode_loop

    mov     x0, #0                     // 返回 0 = 成功

    /* Epilogue */
    ldp     x25, x26, [sp, #112]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #160
    ret

/* ═══════════════════════════════════════════════════════
 * 检测到异常 → SVC exit_group(1)
 * ═══════════════════════════════════════════════════════ */
.L_exit_detected:
    mov     x0, #1
    mov     x8, #94                    // __NR_exit_group
    svc     #0
    /* 不会到达这里 */
    brk     #0

/* ═══════════════════════════════════════════════════════
 * 嵌入数据（converge.py 收敛后填入正确值）：
 *   [0:32]  = permuted encoded payload share
 *   [32:48] = decode table share
 * 不暴露 material[8:16]，避免直接补齐 ARX 末态。
 * ═══════════════════════════════════════════════════════ */
    .balign 8
.L_oracle_data:
    .quad   0x0000000000000000         // payload share A — PLACEHOLDER
    .quad   0x0000000000000000         // payload share B — PLACEHOLDER
    .quad   0x0000000000000000         // payload share C — PLACEHOLDER
    .quad   0x0000000000000000         // payload share D — PLACEHOLDER
    .quad   0x0000000000000000         // decode table A — PLACEHOLDER
    .quad   0x0000000000000000         // decode table B — PLACEHOLDER

oracle_code_end:
    .word   0                          // sentinel
