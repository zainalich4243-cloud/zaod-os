#include <stddef.h>
#include <stdint.h>

#include "address_space.h"
#include "console.h"
#include "gdt.h"
#include "input.h"
#include "interrupts.h"
#include "syscall.h"
#include "task.h"

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t attributes;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed));

struct idt_register {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static struct idt_entry idt[256] __attribute__((aligned(16)));
extern void *exception_stub_table[32];
extern void *irq_stub_table[16];
extern void syscall_128(void);
static volatile uint64_t ticks;
static bool mouse_available;

static inline void outb(uint16_t port, uint8_t value)
{
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static __attribute__((noreturn)) void halt_forever(void)
{
    __asm__ volatile ("cli");
    for (;;) {
        __asm__ volatile ("hlt");
    }
}

void exception_handler(struct interrupt_frame *frame)
{
    bool user_fault = (frame->code_segment & 3u) == 3u &&
                      task_current_user_mode();
    console_write(user_fault ? "\nUser CPU exception "
                             : "\nFATAL kernel CPU exception ");
    console_write_u64(frame->vector);
    console_write(", error=");
    console_write_hex(frame->error_code);
    console_write(", RIP=");
    console_write_hex(frame->instruction_pointer);
    console_write("\n");

    if (frame->vector == 14) {
        uint64_t fault_address;
        __asm__ volatile ("mov %%cr2, %0" : "=r"(fault_address));
        console_write("Page fault address: ");
        console_write_hex(fault_address);
        console_write("\n");
    }

    if (user_fault) {
        console_write("Terminating faulting user task.\n");
        task_exit();
    }
    halt_forever();
}

static void set_gate(size_t vector, uintptr_t handler, uint16_t selector,
                     uint8_t attributes)
{
    idt[vector] = (struct idt_entry) {
        .offset_low = (uint16_t)handler,
        .selector = selector,
        .ist = 0,
        .attributes = attributes,
        .offset_middle = (uint16_t)(handler >> 16),
        .offset_high = (uint32_t)(handler >> 32),
        .reserved = 0
    };
}

void interrupts_init(void)
{
    for (size_t vector = 0; vector < 32; ++vector) {
        set_gate(vector, (uintptr_t)exception_stub_table[vector],
                 GDT_KERNEL_CODE_SELECTOR, 0x8e);
    }
    for (size_t irq = 0; irq < 16; ++irq) {
        set_gate(32 + irq, (uintptr_t)irq_stub_table[irq],
                 GDT_KERNEL_CODE_SELECTOR, 0x8e);
    }
    set_gate(0x80, (uintptr_t)syscall_128,
             GDT_KERNEL_CODE_SELECTOR, 0xee);

    struct idt_register idtr = {
        .limit = sizeof(idt) - 1,
        .base = (uintptr_t)idt
    };
    __asm__ volatile ("lidt %0" : : "m"(idtr));

    outb(0x20, 0x11);
    outb(0xa0, 0x11);
    outb(0x21, 0x20);
    outb(0xa1, 0x28);
    outb(0x21, 0x04);
    outb(0xa1, 0x02);
    outb(0x21, 0x01);
    outb(0xa1, 0x01);

    uint16_t divisor = 11932;
    outb(0x43, 0x36);
    outb(0x40, (uint8_t)divisor);
    outb(0x40, (uint8_t)(divisor >> 8));

    mouse_available = input_init();
    outb(0xa1, mouse_available ? 0xef : 0xff);
    outb(0x21, 0xf8);
}

struct interrupt_frame *interrupt_dispatch(struct interrupt_frame *frame)
{
    if (frame == NULL) {
        return NULL;
    }

    switch (frame->vector) {
    case 32: {
        ++ticks;
        outb(0x20, 0x20);
        struct interrupt_frame *next = task_schedule(frame);
        if (task_current_pid() != 0) {
            address_space_activate(task_current_address_space_root());
            gdt_set_kernel_stack(task_current_kernel_stack_top());
        }
        return next;
    }
    case 33:
        input_keyboard_irq();
        outb(0x20, 0x20);
        return frame;
    case 44:
        if (mouse_available) {
            input_mouse_irq();
        }
        outb(0xa0, 0x20);
        outb(0x20, 0x20);
        return frame;
    case 128:
        syscall_dispatch(frame);
        return frame;
    default:
        if (frame->vector >= 40 && frame->vector < 48) {
            outb(0xa0, 0x20);
        }
        if (frame->vector >= 32 && frame->vector < 48) {
            outb(0x20, 0x20);
        }
        return frame;
    }
}

uint64_t timer_ticks(void)
{
    return ticks;
}

bool mouse_irq_available(void)
{
    return mouse_available;
}
