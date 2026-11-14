#include "libzaod.h"

#define ZAOD_SYS_OPEN 1
#define ZAOD_SYS_READ 2
#define ZAOD_SYS_WRITE 3
#define ZAOD_SYS_EXEC 4
#define ZAOD_SYS_EXIT 5
#define ZAOD_SYS_PERMISSION 6
#define ZAOD_SYS_INPUT_READ 7
#define ZAOD_SYS_ONBOARDING 8
#define ZAOD_ERROR_NO_SYSCALL 38
#define ZAOD_PERMISSION_COUNT 5

_Static_assert(sizeof(struct zaod_input_event) == 12,
               "ZAOD input event ABI changed");

static int64_t invoke_syscall(uint64_t number, uintptr_t first,
                              uintptr_t second, uintptr_t third)
{
#if defined(__x86_64__)
    register uint64_t result __asm__("rax") = number;
    register uintptr_t argument0 __asm__("rdi") = first;
    register uintptr_t argument1 __asm__("rsi") = second;
    register uintptr_t argument2 __asm__("rdx") = third;
    __asm__ volatile ("int $0x80"
                      : "+a"(result)
                      : "D"(argument0), "S"(argument1), "d"(argument2)
                      : "memory", "cc", "rcx", "r11");
    return (int64_t)result;
#else
    (void)number;
    (void)first;
    (void)second;
    (void)third;
    return -ZAOD_ERROR_NO_SYSCALL;
#endif
}

int64_t zaod_open(const char *path, uint32_t flags)
{
    return invoke_syscall(ZAOD_SYS_OPEN, (uintptr_t)path, flags, 0);
}

int64_t zaod_read(int64_t descriptor, void *buffer, size_t size)
{
    return invoke_syscall(ZAOD_SYS_READ, (uintptr_t)descriptor,
                          (uintptr_t)buffer, size);
}

int64_t zaod_write(int64_t descriptor, const void *buffer, size_t size)
{
    return invoke_syscall(ZAOD_SYS_WRITE, (uintptr_t)descriptor,
                          (uintptr_t)buffer, size);
}

int64_t zaod_exec(const char *path)
{
    return invoke_syscall(ZAOD_SYS_EXEC, (uintptr_t)path, 0, 0);
}

int64_t zaod_request_perm(enum zaod_permission permission)
{
    if (permission < ZAOD_PERMISSION_CAMERA ||
        permission >= ZAOD_PERMISSION_COUNT) {
        return -22;
    }
    return invoke_syscall(ZAOD_SYS_PERMISSION, (uintptr_t)permission, 0, 0);
}

int64_t zaod_input_read(struct zaod_input_event *event)
{
    return invoke_syscall(ZAOD_SYS_INPUT_READ, (uintptr_t)event, 0, 0);
}

int64_t zaod_ui_draw_onboarding(uint8_t language, uint8_t pin_length)
{
    return invoke_syscall(ZAOD_SYS_ONBOARDING, language, pin_length, 0);
}

int64_t zaod_exit(void)
{
    return invoke_syscall(ZAOD_SYS_EXIT, 0, 0, 0);
}
