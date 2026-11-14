#ifndef ZAOD_GDT_H
#define ZAOD_GDT_H

#include <stdbool.h>
#include <stdint.h>

#define GDT_KERNEL_CODE_SELECTOR 0x08u
#define GDT_KERNEL_DATA_SELECTOR 0x10u
#define GDT_USER_DATA_SELECTOR 0x1bu
#define GDT_USER_CODE_SELECTOR 0x23u

bool gdt_init(void);
void gdt_set_kernel_stack(uintptr_t stack_top);

#endif
