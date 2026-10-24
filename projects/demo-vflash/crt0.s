@ Demo Quest V.Flash start-up and its soft-float helpers: hand-written assembly, as a V.Flash firmware's start-up and
@ maths runtime are (the vendor's own, not the compiler's). The helpers only have to link: the demo is decompiled,
@ never run. Written for decompdecomp (CC0).
        .text
        .arm
        .global _start
_start:
        ldr     sp, =0x10FFF000
        ldr     r0, =__bss_start
        ldr     r1, =__bss_end
        mov     r2, #0
1:      cmp     r0, r1
        strlo   r2, [r0], #4
        blo     1b
        bl      demo_main
2:      b       2b

        .global __addsf3
__addsf3:
        mov     r0, r0
        mov     pc, lr

        .global __subsf3
__subsf3:
        eor     r1, r1, #0x80000000
        b       __addsf3

        .global __mulsf3
__mulsf3:
        mov     r0, r1
        mov     pc, lr
        .pool
