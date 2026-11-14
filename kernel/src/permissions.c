#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "permissions.h"

struct app_record {
    bool used;
    struct permission_manifest_policy policy;
};

struct process_record {
    bool used;
    bool system_process;
    bool foreground;
    uint64_t pid;
    size_t app_index;
};

struct permission_grant {
    bool used;
    uint64_t pid;
    enum permission_resource resource;
    enum permission_choice choice;
};

static struct app_record apps[PERMISSION_APP_CAPACITY];
static struct process_record processes[PERMISSION_PROCESS_CAPACITY];
static struct permission_grant grants[PERMISSION_GRANT_CAPACITY];

static bool app_id_valid(const char *app_id, size_t *length)
{
    if (app_id == NULL || app_id[0] == '\0') {
        return false;
    }

    size_t count = 0;
    for (; app_id[count] != '\0'; ++count) {
        char value = app_id[count];
        if (count >= PERMISSION_APP_ID_CAPACITY - 1 ||
            !((value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') ||
              value == '.' || value == '-')) {
            return false;
        }
    }
    if (app_id[0] == '.' || app_id[count - 1] == '.' ||
        app_id[count - 1] == '-') {
        return false;
    }
    if (length != NULL) {
        *length = count;
    }
    return true;
}

static bool app_id_equal(const char *left, const char *right)
{
    size_t left_length;
    size_t right_length;
    if (!app_id_valid(left, &left_length) ||
        !app_id_valid(right, &right_length) ||
        left_length != right_length) {
        return false;
    }
    for (size_t i = 0; i < left_length; ++i) {
        if (left[i] != right[i]) {
            return false;
        }
    }
    return true;
}

static size_t find_app(const char *app_id)
{
    for (size_t i = 0; i < PERMISSION_APP_CAPACITY; ++i) {
        if (apps[i].used && app_id_equal(apps[i].policy.app_id, app_id)) {
            return i;
        }
    }
    return PERMISSION_APP_CAPACITY;
}

static size_t find_process(uint64_t pid)
{
    for (size_t i = 0; i < PERMISSION_PROCESS_CAPACITY; ++i) {
        if (processes[i].used && processes[i].pid == pid) {
            return i;
        }
    }
    return PERMISSION_PROCESS_CAPACITY;
}

static const char *resource_name(enum permission_resource resource)
{
    switch (resource) {
    case PERMISSION_CAMERA:
        return "camera";
    case PERMISSION_MICROPHONE:
        return "microphone";
    case PERMISSION_STORAGE:
        return "storage";
    case PERMISSION_NOTIFICATIONS:
        return "notifications";
    case PERMISSION_NETWORK:
        return "network";
    case PERMISSION_RESOURCE_COUNT:
        break;
    }
    return "invalid";
}

static void revoke_process_grants(uint64_t pid)
{
    for (size_t i = 0; i < PERMISSION_GRANT_CAPACITY; ++i) {
        if (grants[i].used && grants[i].pid == pid) {
            grants[i].used = false;
        }
    }
}

void permission_engine_init(void)
{
    for (size_t i = 0; i < PERMISSION_APP_CAPACITY; ++i) {
        apps[i].used = false;
    }
    for (size_t i = 0; i < PERMISSION_PROCESS_CAPACITY; ++i) {
        processes[i].used = false;
    }
    for (size_t i = 0; i < PERMISSION_GRANT_CAPACITY; ++i) {
        grants[i].used = false;
    }
}

bool permission_register_app(const struct permission_manifest_policy *policy)
{
    if (policy == NULL || !app_id_valid(policy->app_id, NULL) ||
        policy->background_access) {
        return false;
    }

    size_t slot = PERMISSION_APP_CAPACITY;
    for (size_t i = 0; i < PERMISSION_APP_CAPACITY; ++i) {
        if (apps[i].used && app_id_equal(apps[i].policy.app_id, policy->app_id)) {
            slot = i;
            break;
        }
        if (!apps[i].used && slot == PERMISSION_APP_CAPACITY) {
            slot = i;
        }
    }
    if (slot == PERMISSION_APP_CAPACITY) {
        return false;
    }

    for (size_t i = 0; i < PERMISSION_RESOURCE_COUNT; ++i) {
        if (policy->resources[i] < PERMISSION_POLICY_DENY ||
            policy->resources[i] > PERMISSION_POLICY_WHILE_USING) {
            return false;
        }
    }
    apps[slot].policy = *policy;
    apps[slot].used = true;
    return true;
}

bool permission_process_start(uint64_t pid, const char *app_id, bool system_process)
{
    if (pid == 0 || find_process(pid) != PERMISSION_PROCESS_CAPACITY) {
        return false;
    }
    size_t app_index = PERMISSION_APP_CAPACITY;
    if (!system_process) {
        app_index = find_app(app_id);
        if (app_index == PERMISSION_APP_CAPACITY) {
            return false;
        }
    }

    for (size_t i = 0; i < PERMISSION_PROCESS_CAPACITY; ++i) {
        if (!processes[i].used) {
            processes[i] = (struct process_record) {
                .used = true,
                .system_process = system_process,
                .foreground = false,
                .pid = pid,
                .app_index = app_index
            };
            return true;
        }
    }
    return false;
}

bool permission_process_set_foreground(uint64_t pid, bool foreground)
{
    size_t index = find_process(pid);
    if (index == PERMISSION_PROCESS_CAPACITY) {
        return false;
    }
    processes[index].foreground = foreground;
    if (!foreground) {
        revoke_process_grants(pid);
        return processes[index].system_process;
    }
    return true;
}

bool permission_process_background_allowed(uint64_t pid)
{
    size_t index = find_process(pid);
    return index != PERMISSION_PROCESS_CAPACITY &&
           processes[index].system_process;
}

bool permission_has_grant(uint64_t pid, enum permission_resource resource)
{
    size_t process_index = find_process(pid);
    if (process_index == PERMISSION_PROCESS_CAPACITY ||
        !processes[process_index].foreground ||
        resource < PERMISSION_CAMERA ||
        resource >= PERMISSION_RESOURCE_COUNT) {
        return false;
    }
    for (size_t i = 0; i < PERMISSION_GRANT_CAPACITY; ++i) {
        if (grants[i].used && grants[i].pid == pid &&
            grants[i].resource == resource) {
            return true;
        }
    }
    return false;
}

bool permission_request(uint64_t pid,
                        enum permission_resource resource,
                        permission_prompt_fn prompt,
                        void *context)
{
    size_t process_index = find_process(pid);
    if (process_index == PERMISSION_PROCESS_CAPACITY ||
        resource < PERMISSION_CAMERA ||
        resource >= PERMISSION_RESOURCE_COUNT) {
        return false;
    }
    struct process_record *process = &processes[process_index];
    if (process->system_process) {
        return true;
    }
    if (!process->foreground ||
        process->app_index >= PERMISSION_APP_CAPACITY ||
        !apps[process->app_index].used ||
        permission_has_grant(pid, resource) || prompt == NULL) {
        return permission_has_grant(pid, resource);
    }

    enum permission_policy_level maximum =
        apps[process->app_index].policy.resources[resource];
    if (maximum == PERMISSION_POLICY_DENY) {
        console_write("Permission denied by app policy: ");
        console_write(resource_name(resource));
        console_write("\n");
        return false;
    }

    uint32_t choices = PERMISSION_PROMPT_ONLY_THIS_TIME;
    if (maximum == PERMISSION_POLICY_WHILE_USING) {
        choices |= PERMISSION_PROMPT_WHILE_USING;
    }

    const char *app_id = apps[process->app_index].policy.app_id;
    enum permission_choice choice = prompt(app_id, resource, choices, context);
    if (choice == PERMISSION_CHOICE_DENY ||
        (choice == PERMISSION_CHOICE_ONLY_THIS_TIME &&
         (choices & PERMISSION_PROMPT_ONLY_THIS_TIME) == 0) ||
        (choice == PERMISSION_CHOICE_WHILE_USING &&
         (choices & PERMISSION_PROMPT_WHILE_USING) == 0) ||
        (choice != PERMISSION_CHOICE_ONLY_THIS_TIME &&
         choice != PERMISSION_CHOICE_WHILE_USING)) {
        console_write("Permission denied: ");
        console_write(resource_name(resource));
        console_write("\n");
        return false;
    }

    if (choice == PERMISSION_CHOICE_ONLY_THIS_TIME) {
        console_write("Permission granted for this request only: ");
        console_write(resource_name(resource));
        console_write("\n");
        return true;
    }

    for (size_t i = 0; i < PERMISSION_GRANT_CAPACITY; ++i) {
        if (!grants[i].used) {
            grants[i] = (struct permission_grant) {
                .used = true,
                .pid = pid,
                .resource = resource,
                .choice = PERMISSION_CHOICE_WHILE_USING
            };
            console_write("Permission granted for current foreground session: ");
            console_write(resource_name(resource));
            console_write("\n");
            return true;
        }
    }
    console_write("Permission denied: grant table is full\n");
    return false;
}

void permission_process_exit(uint64_t pid)
{
    size_t index = find_process(pid);
    if (index == PERMISSION_PROCESS_CAPACITY) {
        return;
    }
    revoke_process_grants(pid);
    processes[index].used = false;
}
