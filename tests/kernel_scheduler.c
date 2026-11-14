#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "console.h"
#include "block.h"
#include "gdt.h"
#include "permissions.h"
#include "persistent_fs.h"
#include "task.h"

uint64_t block_sector_count(void)
{
    return 0;
}

bool block_read_sector(uint64_t lba, uint8_t sector[BLOCK_SECTOR_SIZE])
{
    (void)lba;
    (void)sector;
    return false;
}

bool block_write_sector(uint64_t lba,
                        const uint8_t sector[BLOCK_SECTOR_SIZE])
{
    (void)lba;
    (void)sector;
    return false;
}

void console_write(const char *text)
{
    (void)text;
}

void console_write_u64(uint64_t value)
{
    (void)value;
}

static void no_op_task(void *argument)
{
    (void)argument;
}

int main(void)
{
    permission_engine_init();
    task_scheduler_init();

    const struct permission_manifest_policy app_policy = {
        .app_id = "gui.test",
        .resources = {
            [PERMISSION_STORAGE] = PERMISSION_POLICY_WHILE_USING
        },
        .background_access = false
    };
    assert(permission_register_app(&app_policy));

    uint64_t system_pid;
    uint64_t app_pid;
    uint64_t user_pid;
    assert(task_spawn(NULL, true, no_op_task, NULL, &system_pid));
    assert(task_spawn("gui.test", false, no_op_task, NULL, &app_pid));
    assert(task_non_system_active_count() == 1);
    assert(task_spawn_user(NULL, true, 0x1000, 0x400000, 0x700008,
                           &user_pid));
    assert(!task_spawn("missing.app", false, no_op_task, NULL, NULL));
    assert(task_state_get(system_pid) == TASK_READY);
    assert(task_state_get(app_pid) == TASK_READY);

    struct interrupt_frame bootstrap_frame = {0};
    struct interrupt_frame *selected = task_schedule(&bootstrap_frame);
    assert(selected != NULL);
    assert(task_current_pid() == system_pid);
    assert(task_state_get(system_pid) == TASK_RUNNING);
    assert(selected->stack_pointer != 0);
    assert(selected->stack_pointer % 16 == 8);
    assert(selected->stack_segment == GDT_KERNEL_DATA_SELECTOR);

    struct interrupt_frame system_context = {0};
    selected = task_schedule(&system_context);
    assert(selected != NULL);
    assert(task_current_pid() == app_pid);
    assert(task_state_get(app_pid) == TASK_RUNNING);
    assert(task_state_get(system_pid) == TASK_READY);

    struct interrupt_frame app_context = {0};
    selected = task_schedule(&app_context);
    assert(task_current_pid() == user_pid);
    assert(selected->instruction_pointer == 0x400000);
    assert(selected->code_segment == GDT_USER_CODE_SELECTOR);
    assert(selected->stack_pointer == 0x700008);
    assert(selected->stack_segment == GDT_USER_DATA_SELECTOR);

    struct interrupt_frame user_context = {0};
    selected = task_schedule(&user_context);
    assert(selected == &system_context);
    assert(task_current_pid() == system_pid);
    task_set_foreground(app_pid, false);
    assert(task_state_get(app_pid) == TASK_SUSPENDED);
    assert(!permission_process_background_allowed(app_pid));

    struct interrupt_frame system_context_after_suspend = {0};
    selected = task_schedule(&system_context_after_suspend);
    assert(task_current_pid() == user_pid);
    assert(task_state_get(app_pid) == TASK_SUSPENDED);

    task_set_foreground(app_pid, true);
    assert(task_state_get(app_pid) == TASK_READY);
    struct interrupt_frame user_context_after_resume = {0};
    selected = task_schedule(&user_context_after_resume);
    assert(task_current_pid() == system_pid);
    struct interrupt_frame system_context_after_resume = {0};
    selected = task_schedule(&system_context_after_resume);
    assert(task_current_pid() == app_pid);
    assert(selected == &app_context);

    puts("kernel scheduler tests passed");
    return 0;
}
