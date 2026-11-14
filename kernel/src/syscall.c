#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "address_space.h"
#include "framebuffer.h"
#include "input.h"
#include "permissions.h"
#include "security.h"
#include "syscall.h"
#include "task.h"
#include "vfs.h"
#include "../loader/exec_zaod.h"

#define ERROR_BAD_SYSCALL 38
#define ERROR_PERMISSION 13
#define ERROR_NO_DEVICE 19
#define ERROR_FAULT 14
#define ERROR_INVALID 22
#define USER_COPY_LIMIT 4096u
#define USER_PATH_CAPACITY 256u

static void exit_current_task(uint64_t pid)
{
    if (pid == task_current_pid()) {
        task_exit();
    }
}

static syscall_exit_handler_fn exit_handler = exit_current_task;
static permission_prompt_fn permission_prompt;

static bool copy_user_path(const struct address_space *space,
                           uintptr_t user_path,
                           char path[USER_PATH_CAPACITY])
{
    if (user_path == 0) {
        return false;
    }
    for (size_t index = 0; index < USER_PATH_CAPACITY; ++index) {
        if (index > UINTPTR_MAX - user_path ||
            !address_space_copy_from_user(
                space, &path[index], user_path + index, 1)) {
            return false;
        }
        if (path[index] == '\0') {
            return index != 0 && path[0] == '/';
        }
    }
    return false;
}

static bool current_security_subject(struct security_subject *subject)
{
    uint64_t pid = task_current_pid();
    bool system_task = task_current_is_system();
    const char *app_id = task_current_app_id();
    if (subject == NULL || pid == 0 || (!system_task && app_id == NULL)) {
        return false;
    }
    *subject = (struct security_subject) {
        .pid = pid,
        .uid = system_task ? 0 : 1000,
        .capabilities = system_task ? SECURITY_CAP_SYSTEM : 0,
        .app_id = app_id
    };
    return true;
}

void syscall_init(void)
{
    exit_handler = exit_current_task;
    permission_prompt = NULL;
}

void syscall_set_exit_handler(syscall_exit_handler_fn handler)
{
    exit_handler = handler == NULL ? exit_current_task : handler;
}

void syscall_set_permission_prompt(permission_prompt_fn prompt)
{
    permission_prompt = prompt;
}

void syscall_dispatch(struct interrupt_frame *frame)
{
    if (frame == NULL) {
        return;
    }

    int64_t result;
    bool from_user = (frame->code_segment & 3u) == 3u;
    const struct address_space user_space = {
        .root_physical = task_current_address_space_root()
    };
    if (from_user && !task_current_user_mode()) {
        frame->rax = (uint64_t)-ERROR_PERMISSION;
        return;
    }
    switch (frame->rax) {
    case ZAOD_SYS_OPEN: {
        if (frame->rsi > UINT32_MAX) {
            result = -ERROR_INVALID;
            break;
        }
        char path[USER_PATH_CAPACITY];
        const char *selected_path = (const char *)(uintptr_t)frame->rdi;
        if (from_user) {
            if (!copy_user_path(&user_space, frame->rdi, path)) {
                result = -ERROR_FAULT;
                break;
            }
            selected_path = path;
        }
        result = vfs_open(selected_path, (uint32_t)frame->rsi);
        break;
    }
    case ZAOD_SYS_READ: {
        size_t size = (size_t)frame->rdx;
        if (from_user && size > USER_COPY_LIMIT) {
            result = -ERROR_FAULT;
            break;
        }
        if (!from_user) {
            result = vfs_read((int64_t)frame->rdi,
                              (void *)(uintptr_t)frame->rsi, size);
            break;
        }
        if (!address_space_user_range_valid(
                &user_space, frame->rsi, size, true)) {
            result = -ERROR_FAULT;
            break;
        }
        uint8_t buffer[USER_COPY_LIMIT];
        result = vfs_read((int64_t)frame->rdi, buffer, size);
        if (result > 0 &&
            !address_space_copy_to_user(&user_space, frame->rsi, buffer,
                                        (size_t)result)) {
            result = -ERROR_FAULT;
        }
        break;
    }
    case ZAOD_SYS_WRITE: {
        size_t size = (size_t)frame->rdx;
        if (from_user && size > USER_COPY_LIMIT) {
            result = -ERROR_FAULT;
            break;
        }
        if (!from_user) {
            result = vfs_write((int64_t)frame->rdi,
                               (const void *)(uintptr_t)frame->rsi, size);
            break;
        }
        uint8_t buffer[USER_COPY_LIMIT];
        if (!address_space_copy_from_user(&user_space, buffer, frame->rsi,
                                          size)) {
            result = -ERROR_FAULT;
            break;
        }
        result = vfs_write((int64_t)frame->rdi, buffer, size);
        break;
    }
    case ZAOD_SYS_EXEC: {
        struct security_subject subject;
        const char *path = (const char *)(uintptr_t)frame->rdi;
        char user_path[USER_PATH_CAPACITY];
        if (from_user) {
            if (!copy_user_path(&user_space, frame->rdi, user_path)) {
                result = -ERROR_FAULT;
                break;
            }
            path = user_path;
        }
        if (!current_security_subject(&subject) ||
            !task_current_is_system()) {
            result = -ERROR_PERMISSION;
        } else {
            uint64_t child_pid = 0;
            result = zaod_exec_package_path(path, &child_pid);
        }
        break;
    }
    case ZAOD_SYS_EXIT: {
        uint64_t pid = task_current_pid();
        if (pid == 0) {
            result = -ERROR_PERMISSION;
        } else {
            exit_handler(pid);
            result = 0;
        }
        break;
    }
    case ZAOD_SYS_PERMISSION: {
        uint64_t pid = task_current_pid();
        enum permission_resource resource =
            (enum permission_resource)frame->rdi;
        result = permission_request(pid, resource, permission_prompt, NULL)
            ? 0
            : -ERROR_PERMISSION;
        break;
    }
    case ZAOD_SYS_INPUT_READ: {
        if (!task_current_is_system() || frame->rdi == 0) {
            result = -ERROR_PERMISSION;
            break;
        }
        struct input_event event;
        if (from_user && !address_space_user_range_valid(
                &user_space, frame->rdi, sizeof(event), true)) {
            result = -ERROR_FAULT;
            break;
        }
        if (!input_event_pop(&event)) {
            result = 0;
        } else if (from_user) {
            result = address_space_copy_to_user(
                &user_space, frame->rdi, &event, sizeof(event))
                ? 1
                : -ERROR_FAULT;
        } else {
            *(struct input_event *)(uintptr_t)frame->rdi = event;
            result = 1;
        }
        break;
    }
    case ZAOD_SYS_ONBOARDING:
        if (!task_current_is_system()) {
            result = -ERROR_PERMISSION;
        } else if (!framebuffer_ready()) {
            result = -ERROR_NO_DEVICE;
        } else if (frame->rdi > 2 || frame->rsi > 8) {
            result = -ERROR_FAULT;
        } else {
            framebuffer_draw_onboarding_state(
                (uint8_t)frame->rdi, (uint8_t)frame->rsi);
            result = 0;
        }
        break;
    case ZAOD_SYS_DESKTOP_DRAW:
        if (!task_current_is_system()) {
            result = -ERROR_PERMISSION;
        } else if (!framebuffer_ready()) {
            result = -ERROR_NO_DEVICE;
        } else if (frame->rdi > 3 || frame->rsi > 4) {
            result = -ERROR_FAULT;
        } else {
            framebuffer_draw_shell((uint8_t)frame->rdi,
                                   (uint8_t)frame->rsi);
            result = 0;
        }
        break;
    default:
        result = -ERROR_BAD_SYSCALL;
        break;
    }
    frame->rax = (uint64_t)result;
}
