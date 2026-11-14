#include <stddef.h>
#include <stdint.h>

#define SYS_EXEC 4
#define SYS_INPUT_READ 7
#define SYS_DESKTOP_DRAW 9

struct user_input_event {
    uint32_t type;
    char key;
    uint8_t reserved0;
    int16_t mouse_dx;
    int16_t mouse_dy;
    uint8_t mouse_buttons;
    uint8_t reserved1;
};

_Static_assert(sizeof(struct user_input_event) == 12,
               "kernel input event ABI changed");

static int64_t invoke_syscall(uint64_t number, uintptr_t first,
                              uintptr_t second)
{
    register uint64_t result __asm__("rax") = number;
    register uintptr_t argument0 __asm__("rdi") = first;
    register uintptr_t argument1 __asm__("rsi") = second;
    __asm__ volatile ("int $0x80"
                      : "+a"(result)
                      : "D"(argument0), "S"(argument1)
                      : "memory", "cc", "rcx", "r11");
    return (int64_t)result;
}

__attribute__((noreturn))
void _start(void)
{
    static const char *const packages[3] = {
        "/opt/zaod/apps/org.zaod.files/package.zaod",
        "/opt/zaod/apps/org.zaod.notes/package.zaod",
        "/opt/zaod/apps/org.zaod.terminal/package.zaod"
    };
    struct user_input_event event;
    uint8_t selection = 0;
    uint8_t status = 0;
    (void)invoke_syscall(SYS_DESKTOP_DRAW, selection, status);

    for (;;) {
        int64_t received = invoke_syscall(
            SYS_INPUT_READ, (uintptr_t)&event, 0);
        if (received <= 0) {
            __asm__ volatile ("pause");
            continue;
        }
        if (event.type != 0) {
            continue;
        }

        if (event.key == 'w' || event.key == 'W') {
            selection = selection == 0 ? 3 : (uint8_t)(selection - 1);
            status = 0;
        } else if (event.key == 's' || event.key == 'S') {
            selection = (uint8_t)((selection + 1) % 4);
            status = 0;
        } else if (event.key == 'b' || event.key == 'B' ||
                   event.key == 'r' || event.key == 'R') {
            status = 0;
        } else if (event.key == '\n' || event.key == '\r') {
            if (selection == 3) {
                status = 4;
            } else {
                int64_t launched = invoke_syscall(
                    SYS_EXEC, (uintptr_t)packages[selection], 0);
                status = launched >= 0
                    ? 3
                    : launched == -2 ? 1 : 2;
            }
        } else {
            continue;
        }
        (void)invoke_syscall(SYS_DESKTOP_DRAW, selection, status);
    }
}
