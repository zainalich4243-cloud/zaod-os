#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gdt.h"
#include "permissions.h"
#include "task.h"
#include "vfs.h"

#define NO_TASK TASK_CAPACITY
#define TASK_INITIAL_RFLAGS 0x202u

struct task_record {
    enum task_state state;
    uint64_t pid;
    bool system_task;
    char app_id[TASK_APP_ID_CAPACITY];
    task_entry_fn entry;
    void *argument;
    uint64_t address_space_root;
    bool user_mode;
    struct interrupt_frame *frame;
    uint8_t stack[TASK_STACK_SIZE] __attribute__((aligned(16)));
};

static struct task_record tasks[TASK_CAPACITY];
static size_t current_task;
static uint64_t next_pid;

static uint16_t current_code_segment(void)
{
    uint16_t selector;
    __asm__ volatile ("mov %%cs, %0" : "=r"(selector));
    return selector;
}

static size_t find_task(uint64_t pid)
{
    for (size_t i = 0; i < TASK_CAPACITY; ++i) {
        if (tasks[i].state != TASK_UNUSED && tasks[i].pid == pid) {
            return i;
        }
    }
    return TASK_CAPACITY;
}

static __attribute__((noreturn)) void task_trampoline(void)
{
    if (current_task < TASK_CAPACITY &&
        tasks[current_task].state == TASK_RUNNING &&
        tasks[current_task].entry != NULL) {
        tasks[current_task].entry(tasks[current_task].argument);
    }
    task_exit();
}

void task_scheduler_init(void)
{
    for (size_t i = 0; i < TASK_CAPACITY; ++i) {
        if (tasks[i].state != TASK_UNUSED) {
            permission_process_exit(tasks[i].pid);
        }
        tasks[i].state = TASK_UNUSED;
        tasks[i].frame = NULL;
        tasks[i].entry = NULL;
        tasks[i].argument = NULL;
        tasks[i].address_space_root = 0;
        tasks[i].user_mode = false;
        tasks[i].app_id[0] = '\0';
    }
    current_task = NO_TASK;
    next_pid = 100;
}

static bool task_spawn_internal(const char *app_id, bool system_task,
                               task_entry_fn entry, void *argument,
                               uint64_t address_space_root, bool user_mode,
                               uintptr_t instruction_pointer,
                               uintptr_t initial_stack_pointer,
                               uint64_t *pid)
{
    if ((!user_mode && entry == NULL) ||
        (user_mode && (instruction_pointer == 0 ||
                       initial_stack_pointer == 0 ||
                       address_space_root == 0)) ||
        (!system_task && app_id == NULL)) {
        return false;
    }

    size_t slot = TASK_CAPACITY;
    for (size_t i = 0; i < TASK_CAPACITY; ++i) {
        if (tasks[i].state == TASK_UNUSED || tasks[i].state == TASK_EXITED) {
            slot = i;
            break;
        }
    }
    if (slot == TASK_CAPACITY || next_pid == UINT64_MAX) {
        return false;
    }

    char stored_app_id[TASK_APP_ID_CAPACITY] = {0};
    if (app_id != NULL) {
        size_t length = 0;
        while (app_id[length] != '\0' && length < TASK_APP_ID_CAPACITY - 1) {
            stored_app_id[length] = app_id[length];
            ++length;
        }
        if (app_id[length] != '\0') {
            return false;
        }
    }

    uint64_t task_pid = next_pid++;
    if (!permission_process_start(task_pid, system_task ? NULL : stored_app_id,
                                  system_task)) {
        return false;
    }
    if (!system_task &&
        !permission_process_set_foreground(task_pid, true)) {
        permission_process_exit(task_pid);
        return false;
    }

    struct task_record *task = &tasks[slot];
    task->pid = task_pid;
    task->system_task = system_task;
    task->entry = entry;
    task->argument = argument;
    task->address_space_root = address_space_root;
    task->user_mode = user_mode;
    for (size_t i = 0; i < TASK_APP_ID_CAPACITY; ++i) {
        task->app_id[i] = stored_app_id[i];
    }

    uintptr_t kernel_stack_top =
        (uintptr_t)(task->stack + sizeof(task->stack));
    kernel_stack_top &= ~(uintptr_t)0xf;
    uintptr_t frame_stack_top = kernel_stack_top - sizeof(uint64_t);
    *(uint64_t *)frame_stack_top = 0;
    if (!user_mode) {
        initial_stack_pointer = frame_stack_top;
    }
    frame_stack_top -= sizeof(struct interrupt_frame);
    struct interrupt_frame *frame =
        (struct interrupt_frame *)frame_stack_top;
    for (size_t i = 0; i < sizeof(*frame) / sizeof(uint64_t); ++i) {
        ((uint64_t *)frame)[i] = 0;
    }
    frame->vector = 32;
    frame->instruction_pointer = user_mode
        ? instruction_pointer
        : (uintptr_t)task_trampoline;
    frame->code_segment = user_mode
        ? GDT_USER_CODE_SELECTOR
        : current_code_segment();
    frame->flags = TASK_INITIAL_RFLAGS;
    frame->stack_pointer = initial_stack_pointer;
    frame->stack_segment = user_mode
        ? GDT_USER_DATA_SELECTOR
        : GDT_KERNEL_DATA_SELECTOR;
    task->frame = frame;
    task->state = TASK_READY;

    if (pid != NULL) {
        *pid = task_pid;
    }
    return true;
}

bool task_spawn(const char *app_id, bool system_task,
                task_entry_fn entry, void *argument, uint64_t *pid)
{
    return task_spawn_internal(app_id, system_task, entry, argument, 0,
                               false, 0, 0, pid);
}

bool task_spawn_user(const char *app_id, bool system_task,
                     uint64_t address_space_root, uintptr_t entry,
                     uintptr_t stack_pointer, uint64_t *pid)
{
    return task_spawn_internal(app_id, system_task, NULL, NULL,
                               address_space_root, true, entry,
                               stack_pointer, pid);
}

struct interrupt_frame *task_schedule(struct interrupt_frame *frame)
{
    if (current_task < TASK_CAPACITY &&
        tasks[current_task].state == TASK_RUNNING) {
        tasks[current_task].frame = frame;
        tasks[current_task].state = TASK_READY;
    }

    size_t start = current_task < TASK_CAPACITY
        ? (current_task + 1) % TASK_CAPACITY
        : 0;
    for (size_t offset = 0; offset < TASK_CAPACITY; ++offset) {
        size_t candidate = (start + offset) % TASK_CAPACITY;
        if (tasks[candidate].state == TASK_READY) {
            current_task = candidate;
            tasks[candidate].state = TASK_RUNNING;
            return tasks[candidate].frame;
        }
    }

    current_task = NO_TASK;
    return frame;
}

void task_set_foreground(uint64_t pid, bool foreground)
{
    size_t index = find_task(pid);
    if (index == TASK_CAPACITY || tasks[index].system_task ||
        tasks[index].state == TASK_EXITED) {
        return;
    }
    (void)permission_process_set_foreground(pid, foreground);
    if (foreground) {
        if (tasks[index].state == TASK_SUSPENDED) {
            tasks[index].state = TASK_READY;
        }
    } else if (tasks[index].state == TASK_READY ||
               tasks[index].state == TASK_RUNNING) {
        tasks[index].state = TASK_SUSPENDED;
    }
}

uint64_t task_current_pid(void)
{
    return current_task < TASK_CAPACITY ? tasks[current_task].pid : 0;
}

const char *task_current_app_id(void)
{
    if (current_task >= TASK_CAPACITY || tasks[current_task].system_task) {
        return NULL;
    }
    return tasks[current_task].app_id;
}

bool task_current_is_system(void)
{
    return current_task < TASK_CAPACITY && tasks[current_task].system_task;
}

size_t task_non_system_active_count(void)
{
    size_t count = 0;
    for (size_t i = 0; i < TASK_CAPACITY; ++i) {
        if (tasks[i].state != TASK_UNUSED && tasks[i].state != TASK_EXITED &&
            !tasks[i].system_task) {
            ++count;
        }
    }
    return count;
}

uint64_t task_current_address_space_root(void)
{
    return current_task < TASK_CAPACITY
        ? tasks[current_task].address_space_root
        : 0;
}

uintptr_t task_current_kernel_stack_top(void)
{
    if (current_task >= TASK_CAPACITY) {
        return 0;
    }
    uintptr_t top = (uintptr_t)(tasks[current_task].stack +
                                sizeof(tasks[current_task].stack));
    return top & ~(uintptr_t)0xf;
}

bool task_current_user_mode(void)
{
    return current_task < TASK_CAPACITY && tasks[current_task].user_mode;
}

enum task_state task_state_get(uint64_t pid)
{
    size_t index = find_task(pid);
    return index == TASK_CAPACITY ? TASK_UNUSED : tasks[index].state;
}

void task_exit(void)
{
    __asm__ volatile ("cli");
    if (current_task < TASK_CAPACITY) {
        struct task_record *task = &tasks[current_task];
        task->state = TASK_EXITED;
        vfs_close_process(task->pid);
        permission_process_exit(task->pid);
        current_task = NO_TASK;
    }
    for (;;) {
        __asm__ volatile ("sti; hlt; cli");
    }
}

void task_scheduler_start(void)
{
    for (;;) {
        __asm__ volatile ("sti; hlt");
    }
}
