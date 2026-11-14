#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "security.h"

static struct security_event events[SECURITY_EVENT_CAPACITY];
static size_t next_event;
static size_t stored_events;
static uint64_t next_sequence = 1;

static bool path_has_prefix(const char *path, const char *prefix)
{
    size_t index = 0;
    while (prefix[index] != '\0') {
        if (path[index] != prefix[index]) {
            return false;
        }
        ++index;
    }
    if (index != 0 && prefix[index - 1] == '/') {
        return true;
    }
    return path[index] == '\0' || path[index] == '/';
}

static bool path_is_canonical_absolute(const char *path)
{
    if (path == NULL || path[0] != '/') {
        return false;
    }

    size_t length = 0;
    for (size_t index = 0; path[index] != '\0'; ++index) {
        if (++length >= SECURITY_PATH_CAPACITY) {
            return false;
        }
        if (path[index] == '/' && path[index + 1] == '/') {
            return false;
        }
        if (path[index] == '/') {
            size_t segment_start = index + 1;
            size_t segment_length = 0;
            while (path[segment_start + segment_length] != '\0' &&
                   path[segment_start + segment_length] != '/') {
                ++segment_length;
            }
            if ((segment_length == 1 && path[segment_start] == '.') ||
                (segment_length == 2 && path[segment_start] == '.' &&
                 path[segment_start + 1] == '.')) {
                return false;
            }
        }
    }

    return true;
}

static bool valid_app_id(const char *app_id)
{
    if (app_id == NULL || app_id[0] == '\0') {
        return false;
    }

    size_t length = 0;
    for (; app_id[length] != '\0'; ++length) {
        char value = app_id[length];
        if (length >= 64 ||
            !((value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') ||
              value == '.' || value == '-')) {
            return false;
        }
    }
    return app_id[0] != '.' && app_id[length - 1] != '.' &&
           app_id[length - 1] != '-';
}

static bool path_is_app_path(const char *path, const char *root,
                             const char *app_id)
{
    if (!valid_app_id(app_id) || !path_has_prefix(path, root)) {
        return false;
    }

    size_t root_length = 0;
    while (root[root_length] != '\0') {
        ++root_length;
    }
    size_t app_length = 0;
    while (app_id[app_length] != '\0') {
        ++app_length;
    }
    if (!path_has_prefix(path + root_length, app_id)) {
        return false;
    }
    return path[root_length + app_length] == '\0' ||
           path[root_length + app_length] == '/';
}

static bool path_is_app_executable(const char *path, const char *app_id)
{
    static const char app_root[] = "/opt/zaod/apps/";
    if (!path_is_app_path(path, app_root, app_id)) {
        return false;
    }

    size_t app_root_length = sizeof(app_root) - 1;
    size_t app_length = 0;
    while (app_id[app_length] != '\0') {
        ++app_length;
    }
    const char *relative = path + app_root_length + app_length;
    if (relative[0] != '/') {
        return false;
    }
    relative++;
    return path_has_prefix(relative, "bin/") && relative[4] != '\0';
}

static const char *operation_name(enum security_operation operation)
{
    switch (operation) {
    case SECURITY_OP_EXEC:
        return "exec";
    case SECURITY_OP_FILE_READ:
        return "read";
    case SECURITY_OP_FILE_WRITE:
        return "write";
    case SECURITY_OP_MODULE_LOAD:
        return "module";
    }
    return "invalid";
}

static void record_event(enum security_operation operation,
                         const struct security_subject *subject,
                         const char *path,
                         enum security_decision decision)
{
    struct security_event *event = &events[next_event];
    event->sequence = next_sequence++;
    event->pid = subject == NULL ? 0 : subject->pid;
    event->uid = subject == NULL ? 0 : subject->uid;
    event->operation = operation;
    event->decision = decision;

    size_t index = 0;
    if (path != NULL) {
        while (index + 1 < sizeof(event->path) && path[index] != '\0') {
            event->path[index] = path[index];
            ++index;
        }
    }
    event->path[index] = '\0';

    next_event = (next_event + 1) % SECURITY_EVENT_CAPACITY;
    if (stored_events < SECURITY_EVENT_CAPACITY) {
        ++stored_events;
    }

    console_write("Security ");
    console_write(decision == SECURITY_DECISION_ALLOW ? "ALLOW " : "DENY ");
    console_write(operation_name(operation));
    console_write(" pid=");
    console_write_u64(event->pid);
    console_write(" uid=");
    console_write_u64(event->uid);
    console_write(" path=");
    console_write(event->path);
    console_write("\n");
}

enum security_decision security_check(enum security_operation operation,
                                      const struct security_subject *subject,
                                      const char *path,
                                      bool executable_verified)
{
    enum security_decision decision = SECURITY_DECISION_ALLOW;

    if (subject == NULL ||
        (operation != SECURITY_OP_EXEC &&
         operation != SECURITY_OP_FILE_READ &&
         operation != SECURITY_OP_FILE_WRITE &&
         operation != SECURITY_OP_MODULE_LOAD)) {
        decision = SECURITY_DECISION_DENY;
    } else {
        bool is_system =
            (subject->capabilities & SECURITY_CAP_SYSTEM) != 0;

        if (operation == SECURITY_OP_MODULE_LOAD) {
            if (!is_system) {
                decision = SECURITY_DECISION_DENY;
            }
        } else if (!path_is_canonical_absolute(path)) {
            decision = SECURITY_DECISION_DENY;
        } else if (!is_system && !valid_app_id(subject->app_id)) {
            decision = SECURITY_DECISION_DENY;
        } else if (operation == SECURITY_OP_EXEC) {
            if (!is_system &&
                (!executable_verified ||
                 !path_is_app_executable(path, subject->app_id))) {
                decision = SECURITY_DECISION_DENY;
            }
        } else if (!is_system && operation == SECURITY_OP_FILE_READ) {
            if (!path_is_app_path(path, "/opt/zaod/apps/", subject->app_id) &&
                !path_is_app_path(path, "/var/lib/zaod/apps/", subject->app_id)) {
                decision = SECURITY_DECISION_DENY;
            }
        } else if (!is_system && operation == SECURITY_OP_FILE_WRITE) {
            if (!path_is_app_path(path, "/var/lib/zaod/apps/", subject->app_id)) {
                decision = SECURITY_DECISION_DENY;
            }
        }
    }

    record_event(operation, subject, path, decision);
    return decision;
}

void security_report_blocked_write(const struct security_subject *subject,
                                   const char *path)
{
    record_event(SECURITY_OP_FILE_WRITE, subject, path,
                 SECURITY_DECISION_DENY);
}

size_t security_event_count(void)
{
    return stored_events;
}

bool security_event_get(size_t index, struct security_event *event)
{
    if (event == NULL || index >= stored_events) {
        return false;
    }

    size_t oldest = (next_event + SECURITY_EVENT_CAPACITY - stored_events) %
                    SECURITY_EVENT_CAPACITY;
    *event = events[(oldest + index) % SECURITY_EVENT_CAPACITY];
    return true;
}
