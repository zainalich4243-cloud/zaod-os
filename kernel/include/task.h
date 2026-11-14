#ifndef ZAOD_TASK_H
#define ZAOD_TASK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TASK_CAPACITY 16
#define TASK_STACK_SIZE 16384
#define TASK_APP_ID_CAPACITY 65

struct interrupt_frame {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;
    uint64_t vector;
    uint64_t error_code;
    uint64_t instruction_pointer;
    uint64_t code_segment;
    uint64_t flags;
    uint64_t stack_pointer;
    uint64_t stack_segment;
};

typedef void (*task_entry_fn)(void *argument);

enum task_state {
    TASK_UNUSED,
    TASK_READY,
    TASK_RUNNING,
    TASK_SUSPENDED,
    TASK_EXITED
};

void task_scheduler_init(void);
bool task_spawn(const char *app_id, bool system_task,
                task_entry_fn entry, void *argument, uint64_t *pid);
bool task_spawn_user(const char *app_id, bool system_task,
                     uint64_t address_space_root, uintptr_t entry,
                     uintptr_t stack_pointer, uint64_t *pid);
struct interrupt_frame *task_schedule(struct interrupt_frame *frame);
uint64_t task_current_address_space_root(void);
uintptr_t task_current_kernel_stack_top(void);
bool task_current_user_mode(void);
void task_set_foreground(uint64_t pid, bool foreground);
uint64_t task_current_pid(void);
const char *task_current_app_id(void);
bool task_current_is_system(void);
size_t task_non_system_active_count(void);
enum task_state task_state_get(uint64_t pid);
void task_exit(void) __attribute__((noreturn));
void task_scheduler_start(void) __attribute__((noreturn));

#endif
