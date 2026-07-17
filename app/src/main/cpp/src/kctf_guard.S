/*
 * Stable executable guard bytes used for soKey derivation.
 * Keep this section independent from generated verification constants so
 * release convergence has a fixed point.
 */
    .section .kctfguard,"ax",@progbits
    .p2align 4
    .globl kctf_guard_start
    .globl kctf_guard_end
    .hidden kctf_guard_start
    .hidden kctf_guard_end

kctf_guard_start:
    movz    x0, #0xE667
    movk    x0, #0x6A09, lsl #16
    movk    x0, #0xAE85, lsl #32
    movk    x0, #0xBB67, lsl #48
    movz    x1, #0xF372
    movk    x1, #0x3C6E, lsl #16
    movk    x1, #0xF53A, lsl #32
    movk    x1, #0xA54F, lsl #48
    eor     x2, x0, x1
    ror     x2, x2, #13
    add     x2, x2, #0x5A5
    eor     x3, x2, x0, ror #29
    add     x3, x3, x1
    ror     x3, x3, #17
    eor     x0, x3, x2
    ret

    .rept 8
    hint    #0
    .endr

kctf_guard_end:
