#ifndef ZAOD_SECURITY_H
#define ZAOD_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SECURITY_EVENT_CAPACITY 64
#define SECURITY_PATH_CAPACITY 128
#define SECURITY_CAP_SYSTEM 0x1u

enum security_operation {
    SECURITY_OP_EXEC,
    SECURITY_OP_FILE_READ,
    SECURITY_OP_FILE_WRITE,
    SECURITY_OP_MODULE_LOAD
};

enum security_decision {
    SECURITY_DECISION_ALLOW,
    SECURITY_DECISION_DENY
};

struct security_subject {
    uint64_t pid;
    uint64_t uid;
    uint32_t capabilities;
    const char *app_id;
};

struct security_event {
    uint64_t sequence;
    uint64_t pid;
    uint64_t uid;
    enum security_operation operation;
    enum security_decision decision;
    char path[SECURITY_PATH_CAPACITY];
};

enum security_decision security_check(enum security_operation operation,
                                      const struct security_subject *subject,
                                      const char *path,
                                      bool executable_verified);
void security_report_blocked_write(const struct security_subject *subject,
                                   const char *path);
size_t security_event_count(void);
bool security_event_get(size_t index, struct security_event *event);

#endif
