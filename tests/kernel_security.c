#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "console.h"
#include "security.h"

void console_write(const char *text)
{
    (void)text;
}

void console_write_u64(uint64_t value)
{
    (void)value;
}

static struct security_subject unprivileged = {
    .pid = 42,
    .uid = 1000,
    .capabilities = 0,
    .app_id = "sample.app"
};

static struct security_subject system_task = {
    .pid = 1,
    .uid = 0,
    .capabilities = SECURITY_CAP_SYSTEM
};

int main(void)
{
    char overlong_path[SECURITY_PATH_CAPACITY + 1];
    for (size_t i = 0; i < SECURITY_PATH_CAPACITY; ++i) {
        overlong_path[i] = 'a';
    }
    overlong_path[SECURITY_PATH_CAPACITY] = '\0';

    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/etc/passwd", false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/usr/local/bin/tool", false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/home/etc/notes", false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/etcetera/notes", false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/tmp/../etc/passwd", false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/tmp//file", false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          overlong_path, false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_EXEC, &unprivileged,
                          "/tmp/tool", false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_EXEC, &unprivileged,
                          "/tmp/tool", true) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_MODULE_LOAD, &unprivileged,
                          NULL, false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_MODULE_LOAD, &system_task,
                          NULL, false) == SECURITY_DECISION_ALLOW);
    assert(security_check(SECURITY_OP_FILE_WRITE, &system_task,
                          "/etc/passwd", false) == SECURITY_DECISION_ALLOW);

    assert(security_check(SECURITY_OP_FILE_READ, &unprivileged,
                          "/opt/zaod/apps/sample.app/bin/sample",
                          false) == SECURITY_DECISION_ALLOW);
    assert(security_check(SECURITY_OP_FILE_READ, &unprivileged,
                          "/opt/zaod/apps/other.app/bin/sample",
                          false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_READ, &unprivileged,
                          "/etc/passwd", false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/opt/zaod/apps/sample.app/bin/sample",
                          false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/var/lib/zaod/apps/sample.app/state",
                          false) == SECURITY_DECISION_ALLOW);
    assert(security_check(SECURITY_OP_FILE_WRITE, &unprivileged,
                          "/var/lib/zaod/apps/other.app/state",
                          false) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_EXEC, &unprivileged,
                          "/opt/zaod/apps/sample.app/bin/sample",
                          true) == SECURITY_DECISION_ALLOW);
    assert(security_check(SECURITY_OP_EXEC, &unprivileged,
                          "/opt/zaod/apps/other.app/bin/sample",
                          true) == SECURITY_DECISION_DENY);
    assert(security_check(SECURITY_OP_FILE_READ, &unprivileged,
                          NULL, false) == SECURITY_DECISION_DENY);

    assert(security_event_count() == 21);
    struct security_event event;
    assert(security_event_get(0, &event));
    assert(event.operation == SECURITY_OP_FILE_WRITE);
    assert(event.decision == SECURITY_DECISION_DENY);
    assert(event.pid == unprivileged.pid);
    assert(event.uid == unprivileged.uid);
    assert(event.path[0] == '/');
    assert(!security_event_get(security_event_count(), &event));

    for (size_t i = 0; i < SECURITY_EVENT_CAPACITY + 2; ++i) {
        assert(security_check(SECURITY_OP_FILE_WRITE, &system_task,
                              "/tmp/test", false) == SECURITY_DECISION_ALLOW);
    }
    assert(security_event_count() == SECURITY_EVENT_CAPACITY);
    assert(security_event_get(0, &event));
    assert(event.sequence == 24);

    puts("kernel security policy tests passed");
    return 0;
}
