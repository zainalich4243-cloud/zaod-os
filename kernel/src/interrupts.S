.section .text

.macro ISR_NOERR vector
.global exception_\vector
exception_\vector:
    pushq $0
    pushq $\vector
    jmp exception_common
.endm

.macro ISR_ERR vector
.global exception_\vector
exception_\vector:
    pushq $\vector
    jmp exception_common
.endm

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29
ISR_ERR   30
ISR_NOERR 31

.global exception_common
exception_common:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    cld
    movq %rsp, %rbx
    movq %rsp, %rdi
    andq $-16, %rsp
    call exception_handler
    movq %rbx, %rsp

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp
    iretq

.section .rodata
.align 8
.global exception_stub_table
exception_stub_table:
.quad exception_0, exception_1, exception_2, exception_3
.quad exception_4, exception_5, exception_6, exception_7
.quad exception_8, exception_9, exception_10, exception_11
.quad exception_12, exception_13, exception_14, exception_15
.quad exception_16, exception_17, exception_18, exception_19
.quad exception_20, exception_21, exception_22, exception_23
.quad exception_24, exception_25, exception_26, exception_27
.quad exception_28, exception_29, exception_30, exception_31

.section .note.GNU-stack,"",@progbits

.section .text

.macro IRQ_STUB irq
.global irq_\irq
irq_\irq:
    pushq $0
    pushq $(32 + \irq)
    jmp irq_common
.endm

IRQ_STUB 0
IRQ_STUB 1
IRQ_STUB 2
IRQ_STUB 3
IRQ_STUB 4
IRQ_STUB 5
IRQ_STUB 6
IRQ_STUB 7
IRQ_STUB 8
IRQ_STUB 9
IRQ_STUB 10
IRQ_STUB 11
IRQ_STUB 12
IRQ_STUB 13
IRQ_STUB 14
IRQ_STUB 15

.global syscall_128
syscall_128:
    pushq $0
    pushq $128
    jmp irq_common

irq_common:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    cld
    movq %rsp, %rdi
    andq $-16, %rsp
    call interrupt_dispatch
    movq %rax, %rsp

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp
    iretq

.section .rodata
.align 8
.global irq_stub_table
irq_stub_table:
.quad irq_0, irq_1, irq_2, irq_3
.quad irq_4, irq_5, irq_6, irq_7
.quad irq_8, irq_9, irq_10, irq_11
.quad irq_12, irq_13, irq_14, irq_15

.section .note.GNU-stack,"",@progbits
