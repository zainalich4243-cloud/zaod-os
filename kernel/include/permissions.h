#ifndef ZAOD_PERMISSIONS_H
#define ZAOD_PERMISSIONS_H

#include <stdbool.h>
#include <stdint.h>

#define PERMISSION_APP_ID_CAPACITY 65
#define PERMISSION_APP_CAPACITY 32
#define PERMISSION_PROCESS_CAPACITY 64
#define PERMISSION_GRANT_CAPACITY 128

enum permission_resource {
    PERMISSION_CAMERA,
    PERMISSION_MICROPHONE,
    PERMISSION_STORAGE,
    PERMISSION_NOTIFICATIONS,
    PERMISSION_NETWORK,
    PERMISSION_RESOURCE_COUNT
};

enum permission_policy_level {
    PERMISSION_POLICY_DENY,
    PERMISSION_POLICY_ONE_TIME,
    PERMISSION_POLICY_WHILE_USING
};

enum permission_choice {
    PERMISSION_CHOICE_DENY,
    PERMISSION_CHOICE_ONLY_THIS_TIME,
    PERMISSION_CHOICE_WHILE_USING
};

#define PERMISSION_PROMPT_ONLY_THIS_TIME 0x1u
#define PERMISSION_PROMPT_WHILE_USING 0x2u

struct permission_manifest_policy {
    char app_id[PERMISSION_APP_ID_CAPACITY];
    enum permission_policy_level resources[PERMISSION_RESOURCE_COUNT];
    bool background_access;
};

typedef enum permission_choice (*permission_prompt_fn)(
    const char *app_id,
    enum permission_resource resource,
    uint32_t choices,
    void *context
);

void permission_engine_init(void);
bool permission_register_app(const struct permission_manifest_policy *policy);
bool permission_process_start(uint64_t pid, const char *app_id, bool system_process);
bool permission_process_set_foreground(uint64_t pid, bool foreground);
bool permission_process_background_allowed(uint64_t pid);
bool permission_request(uint64_t pid,
                       enum permission_resource resource,
                       permission_prompt_fn prompt,
                       void *context);
bool permission_has_grant(uint64_t pid, enum permission_resource resource);
void permission_process_exit(uint64_t pid);

#endif
