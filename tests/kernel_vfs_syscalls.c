#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"
#include "block.h"
#include "input.h"
#include "permissions.h"
#include "persistent_fs.h"
#include "security.h"
#include "syscall.h"
#include "task.h"
#include "vfs.h"

#define ARCHIVE_CAPACITY 2048
#define TEST_DISK_SECTORS 65553u

static size_t exec_package_calls;

int64_t zaod_exec_package_path(const char *path, uint64_t *child_pid)
{
    (void)path;
    (void)child_pid;
    ++exec_package_calls;
    return -13;
}

static uint8_t archive_bytes[ARCHIVE_CAPACITY];
static size_t archive_size;
static uint64_t exited_pid;
static uint8_t *block_device;

static bool has_blocked_write_event(const char *path)
{
    for (size_t index = 0; index < security_event_count(); ++index) {
        struct security_event event;
        if (security_event_get(index, &event) &&
            event.operation == SECURITY_OP_FILE_WRITE &&
            event.decision == SECURITY_DECISION_DENY &&
            strcmp(event.path, path) == 0) {
            return true;
        }
    }
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

void console_write_hex(uint64_t value)
{
    (void)value;
}

uint64_t block_sector_count(void)
{
    return TEST_DISK_SECTORS;
}

bool block_read_sector(uint64_t lba, uint8_t sector[BLOCK_SECTOR_SIZE])
{
    if (lba >= TEST_DISK_SECTORS || sector == NULL) {
        return false;
    }
    memcpy(sector, block_device + lba * BLOCK_SECTOR_SIZE,
           BLOCK_SECTOR_SIZE);
    return true;
}

bool block_write_sector(uint64_t lba,
                        const uint8_t sector[BLOCK_SECTOR_SIZE])
{
    if (lba >= TEST_DISK_SECTORS || sector == NULL) {
        return false;
    }
    memcpy(block_device + lba * BLOCK_SECTOR_SIZE, sector,
           BLOCK_SECTOR_SIZE);
    return true;
}

static void append_entry(const char *name, const uint8_t *data,
                         size_t data_size, uint32_t mode, uint32_t inode)
{
    uint32_t fields[13] = {
        inode, mode, 0, 0, 1, 0, (uint32_t)data_size,
        0, 0, 0, 0, (uint32_t)strlen(name) + 1, 0
    };
    size_t start = archive_size;
    memcpy(archive_bytes + archive_size, "070701", 6);
    archive_size += 6;
    for (size_t i = 0; i < 13; ++i) {
        int written = snprintf((char *)archive_bytes + archive_size, 9,
                               "%08x", fields[i]);
        assert(written == 8);
        archive_size += 8;
    }
    assert(archive_size - start == 110);
    memcpy(archive_bytes + archive_size, name, strlen(name) + 1);
    archive_size += strlen(name) + 1;
    while ((archive_size & 3u) != 0) {
        archive_bytes[archive_size++] = 0;
    }
    if (data_size != 0) {
        memcpy(archive_bytes + archive_size, data, data_size);
        archive_size += data_size;
    }
    while ((archive_size & 3u) != 0) {
        archive_bytes[archive_size++] = 0;
    }
}

static void build_archive(void)
{
    static const uint8_t release[] = "ZAOD\n";
    static const uint8_t application[] = "APP";
    archive_size = 0;
    append_entry("etc", NULL, 0, 0040755, 1);
    append_entry("etc/zaod-release", release, sizeof(release) - 1,
                 0100644, 2);
    append_entry("opt/zaod/apps/gui.test/bin/app", application,
                 sizeof(application) - 1, 0100755, 3);
    append_entry("TRAILER!!!", NULL, 0, 0, 4);
}

static enum permission_choice grant_storage(
    const char *app_id,
    enum permission_resource resource,
    uint32_t choices,
    void *context)
{
    (void)context;
    assert(strcmp(app_id, "gui.test") == 0);
    assert(resource == PERMISSION_STORAGE);
    assert((choices & PERMISSION_PROMPT_WHILE_USING) != 0);
    return PERMISSION_CHOICE_WHILE_USING;
}

static void test_exit_handler(uint64_t pid)
{
    exited_pid = pid;
}

static void no_op_task(void *argument)
{
    (void)argument;
}

static int64_t invoke_syscall(uint64_t number, uint64_t arg0,
                             uint64_t arg1, uint64_t arg2)
{
    struct interrupt_frame frame = {
        .rax = number,
        .rdi = arg0,
        .rsi = arg1,
        .rdx = arg2
    };
    syscall_dispatch(&frame);
    return (int64_t)frame.rax;
}

int main(void)
{
    build_archive();
    block_device = calloc(TEST_DISK_SECTORS, BLOCK_SECTOR_SIZE);
    assert(block_device != NULL);
    assert(persistent_fs_format());
    assert(persistent_fs_mount());
    assert(vfs_init(archive_bytes, archive_size));
    assert(!vfs_init(archive_bytes, archive_size - 1));
    assert(vfs_init(archive_bytes, archive_size));

    permission_engine_init();
    task_scheduler_init();
    syscall_init();
    syscall_set_exit_handler(test_exit_handler);
    syscall_set_permission_prompt(grant_storage);
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
    assert(task_spawn(NULL, true, no_op_task, NULL, &system_pid));
    assert(task_spawn("gui.test", false, no_op_task, NULL, &app_pid));
    struct interrupt_frame bootstrap = {0};
    (void)task_schedule(&bootstrap);
    struct input_event input = {0};
    assert(invoke_syscall(ZAOD_SYS_INPUT_READ, (uintptr_t)&input, 0, 0) == 0);
    assert(invoke_syscall(ZAOD_SYS_ONBOARDING, 0, 0, 0) < 0);

    int64_t descriptor = invoke_syscall(
        ZAOD_SYS_OPEN, (uintptr_t)"/home/test/blocked",
        VFS_OPEN_WRITE | VFS_OPEN_CREATE, 0);
    assert(descriptor >= 0);
    assert(invoke_syscall(ZAOD_SYS_WRITE, (uint64_t)descriptor,
                          (uintptr_t)"a", 1) == 1);
    assert(invoke_syscall(ZAOD_SYS_WRITE, (uint64_t)descriptor,
                          (uintptr_t)"bc", 2) == -13);
    size_t persistent_slot;
    size_t persistent_size;
    assert(persistent_fs_open("/home/test/blocked", false, false,
                              &persistent_slot, &persistent_size) == 0);
    assert(persistent_size == 1);
    assert(has_blocked_write_event("/home/test/blocked"));

    descriptor = invoke_syscall(
        ZAOD_SYS_OPEN, (uintptr_t)"/etc/zaod-release", VFS_OPEN_READ, 0);
    assert(descriptor >= 0);
    char release[8] = {0};
    assert(invoke_syscall(ZAOD_SYS_READ, (uint64_t)descriptor,
                          (uintptr_t)release, sizeof(release)) == 5);
    assert(strcmp(release, "ZAOD\n") == 0);

    struct interrupt_frame system_context = {0};
    (void)task_schedule(&system_context);
    assert(task_current_pid() == app_pid);
    task_set_foreground(app_pid, true);
    assert(invoke_syscall(ZAOD_SYS_INPUT_READ, (uintptr_t)&input, 0, 0) < 0);
    assert(invoke_syscall(ZAOD_SYS_ONBOARDING, 0, 0, 0) < 0);
    assert(invoke_syscall(ZAOD_SYS_DESKTOP_DRAW, 0, 0, 0) == -13);

    assert(invoke_syscall(ZAOD_SYS_OPEN,
        (uintptr_t)"/opt/zaod/apps/gui.test/bin/app", VFS_OPEN_READ, 0) < 0);
    assert(invoke_syscall(ZAOD_SYS_OPEN,
        (uintptr_t)"/etc/zaod-release", VFS_OPEN_READ, 0) < 0);
    assert(invoke_syscall(ZAOD_SYS_PERMISSION, PERMISSION_STORAGE, 0, 0) == 0);

    descriptor = invoke_syscall(
        ZAOD_SYS_OPEN,
        (uintptr_t)"/opt/zaod/apps/gui.test/bin/app",
        VFS_OPEN_READ, 0);
    assert(descriptor >= 0);
    char application[4] = {0};
    assert(invoke_syscall(ZAOD_SYS_READ, (uint64_t)descriptor,
                          (uintptr_t)application, sizeof(application)) == 3);
    assert(strcmp(application, "APP") == 0);

    const char settings[] = "lang=en";
    descriptor = invoke_syscall(
        ZAOD_SYS_OPEN,
        (uintptr_t)"/var/lib/zaod/apps/gui.test/settings",
        VFS_OPEN_WRITE | VFS_OPEN_CREATE, 0);
    assert(descriptor >= 0);
    assert(invoke_syscall(ZAOD_SYS_WRITE, (uint64_t)descriptor,
                          (uintptr_t)settings, sizeof(settings)) ==
           (int64_t)sizeof(settings));
    assert(invoke_syscall(ZAOD_SYS_OPEN,
        (uintptr_t)"/var/lib/zaod/apps/other.app/settings",
        VFS_OPEN_WRITE | VFS_OPEN_CREATE, 0) < 0);

    descriptor = invoke_syscall(
        ZAOD_SYS_OPEN,
        (uintptr_t)"/var/lib/zaod/apps/gui.test/blocked",
        VFS_OPEN_WRITE | VFS_OPEN_CREATE, 0);
    assert(descriptor >= 0);
    assert(invoke_syscall(ZAOD_SYS_WRITE, (uint64_t)descriptor,
                          (uintptr_t)"a", 1) == 1);
    assert(invoke_syscall(ZAOD_SYS_WRITE, (uint64_t)descriptor,
                          (uintptr_t)"bc", 2) == -13);
    descriptor = invoke_syscall(
        ZAOD_SYS_OPEN,
        (uintptr_t)"/var/lib/zaod/apps/gui.test/blocked",
        VFS_OPEN_READ, 0);
    assert(descriptor >= 0);
    char blocked_contents[4] = {0};
    assert(invoke_syscall(ZAOD_SYS_READ, (uint64_t)descriptor,
                          (uintptr_t)blocked_contents,
                          sizeof(blocked_contents)) == 1);
    assert(strcmp(blocked_contents, "a") == 0);
    assert(has_blocked_write_event(
        "/var/lib/zaod/apps/gui.test/blocked"));

    descriptor = invoke_syscall(
        ZAOD_SYS_OPEN,
        (uintptr_t)"/var/lib/zaod/apps/gui.test/settings",
        VFS_OPEN_READ, 0);
    assert(descriptor >= 0);
    int64_t stale_read_descriptor = descriptor;
    char stored_settings[sizeof(settings)] = {0};
    assert(invoke_syscall(ZAOD_SYS_READ, (uint64_t)descriptor,
                          (uintptr_t)stored_settings,
                          sizeof(stored_settings)) ==
           (int64_t)sizeof(stored_settings));
    assert(strcmp(stored_settings, settings) == 0);

    const char shorter_settings[] = "fr";
    descriptor = invoke_syscall(
        ZAOD_SYS_OPEN,
        (uintptr_t)"/var/lib/zaod/apps/gui.test/settings",
        VFS_OPEN_WRITE | VFS_OPEN_TRUNCATE, 0);
    assert(descriptor >= 0);
    assert(invoke_syscall(ZAOD_SYS_WRITE, (uint64_t)descriptor,
                          (uintptr_t)shorter_settings,
                          sizeof(shorter_settings)) ==
           (int64_t)sizeof(shorter_settings));
    assert(invoke_syscall(ZAOD_SYS_READ, (uint64_t)stale_read_descriptor,
                          (uintptr_t)stored_settings,
                          sizeof(stored_settings)) == 0);
    descriptor = invoke_syscall(
        ZAOD_SYS_OPEN,
        (uintptr_t)"/var/lib/zaod/apps/gui.test/settings",
        VFS_OPEN_READ, 0);
    assert(descriptor >= 0);
    char truncated_settings[sizeof(settings)] = {0};
    assert(invoke_syscall(ZAOD_SYS_READ, (uint64_t)descriptor,
                          (uintptr_t)truncated_settings,
                          sizeof(truncated_settings)) ==
           (int64_t)sizeof(shorter_settings));
    assert(strcmp(truncated_settings, shorter_settings) == 0);
    assert(invoke_syscall(
        ZAOD_SYS_OPEN,
        (uintptr_t)"/var/lib/zaod/apps/gui.test/settings",
        VFS_OPEN_READ | VFS_OPEN_TRUNCATE, 0) < 0);

    assert(invoke_syscall(ZAOD_SYS_EXEC,
        (uintptr_t)"/opt/zaod/apps/gui.test/package.zaod", 0, 0) == -13);
    assert(exec_package_calls == 0);
    assert(invoke_syscall(999, 0, 0, 0) < 0);
    assert(invoke_syscall(ZAOD_SYS_EXIT, 0, 0, 0) == 0);
    assert(exited_pid == app_pid);
    (void)system_pid;

    free(block_device);
    puts("kernel VFS and syscall tests passed");
    return 0;
}
