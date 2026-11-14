#include <stddef.h>
#include <stdint.h>

#include "gdt.h"

#define GDT_TSS_SELECTOR 0x28u
#define EFER_MSR 0xc0000080u
#define EFER_NXE (1u << 11)
#define CPUID_EXT_FEATURES 0x80000001u
#define CPUID_NX (1u << 20)

struct task_state_segment {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;
} __attribute__((packed));

struct table_register {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static uint64_t gdt[7] __attribute__((aligned(16)));
static struct task_state_segment tss __attribute__((aligned(16)));

static bool enable_nx(void)
{
    uint32_t eax = 0x80000000u;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    __asm__ volatile ("cpuid"
                      : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if (eax < CPUID_EXT_FEATURES) {
        return false;
    }

    eax = CPUID_EXT_FEATURES;
    __asm__ volatile ("cpuid"
                      : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    if ((edx & CPUID_NX) == 0) {
        return false;
    }

    uint32_t msr_low;
    uint32_t msr_high;
    __asm__ volatile ("rdmsr"
                      : "=a"(msr_low), "=d"(msr_high)
                      : "c"(EFER_MSR));
    msr_low |= EFER_NXE;
    __asm__ volatile ("wrmsr"
                      :
                      : "a"(msr_low), "d"(msr_high), "c"(EFER_MSR)
                      : "memory");
    return true;
}

bool gdt_init(void)
{
    if (!enable_nx()) {
        return false;
    }

    gdt[0] = 0;
    gdt[1] = 0x00af9a000000ffffull;
    gdt[2] = 0x00cf92000000ffffull;
    gdt[3] = 0x00cff2000000ffffull;
    gdt[4] = 0x00affa000000ffffull;
    tss = (struct task_state_segment) {
        .iomap_base = sizeof(tss)
    };

    uintptr_t base = (uintptr_t)&tss;
    uint32_t limit = sizeof(tss) - 1;
    gdt[5] = (limit & 0xffffu) |
             ((base & 0xffffffu) << 16) |
             (0x89ull << 40) |
             ((uint64_t)((limit >> 16) & 0x0fu) << 48) |
             (((base >> 24) & 0xffu) << 56);
    gdt[6] = base >> 32;

    const struct table_register gdtr = {
        .limit = sizeof(gdt) - 1,
        .base = (uintptr_t)gdt
    };
    __asm__ volatile (
        "lgdt %0\n"
        "pushq $0x08\n"
        "leaq 1f(%%rip), %%rax\n"
        "pushq %%rax\n"
        "lretq\n"
        "1:\n"
        "movw $0x10, %%ax\n"
        "movw %%ax, %%ds\n"
        "movw %%ax, %%es\n"
        "movw %%ax, %%ss\n"
        "movw $0x28, %%ax\n"
        "ltr %%ax\n"
        :
        : "m"(gdtr)
        : "rax", "memory");
    return true;
}

void gdt_set_kernel_stack(uintptr_t stack_top)
{
    tss.rsp0 = stack_top & ~(uintptr_t)0xfu;
}
