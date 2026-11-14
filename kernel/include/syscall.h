#ifndef ZAOD_SYSCALL_H
#define ZAOD_SYSCALL_H

#include <stdint.h>

#include "permissions.h"
#include "task.h"

enum zaod_syscall_number {
    ZAOD_SYS_OPEN = 1,
    ZAOD_SYS_READ = 2,
    ZAOD_SYS_WRITE = 3,
    ZAOD_SYS_EXEC = 4,
    ZAOD_SYS_EXIT = 5,
    ZAOD_SYS_PERMISSION = 6,
    ZAOD_SYS_INPUT_READ = 7,
    ZAOD_SYS_ONBOARDING = 8,
    ZAOD_SYS_DESKTOP_DRAW = 9
};

typedef void (*syscall_exit_handler_fn)(uint64_t pid);

void syscall_init(void);
void syscall_set_exit_handler(syscall_exit_handler_fn handler);
void syscall_set_permission_prompt(permission_prompt_fn prompt);
void syscall_dispatch(struct interrupt_frame *frame);

#endif
