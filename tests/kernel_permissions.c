#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "console.h"
#include "permissions.h"

void console_write(const char *text)
{
    (void)text;
}

void console_write_u64(uint64_t value)
{
    (void)value;
}

struct prompt_test {
    enum permission_choice choice;
    uint32_t choices;
    size_t calls;
};

static enum permission_choice test_prompt(const char *app_id,
                                          enum permission_resource resource,
                                          uint32_t choices,
                                          void *context)
{
    struct prompt_test *test = context;
    assert(strcmp(app_id, "sample.app") == 0);
    assert(resource < PERMISSION_RESOURCE_COUNT);
    test->choices = choices;
    ++test->calls;
    return test->choice;
}

int main(void)
{
    permission_engine_init();

    struct permission_manifest_policy policy = {
        .app_id = "sample.app",
        .resources = {
            [PERMISSION_CAMERA] = PERMISSION_POLICY_WHILE_USING,
            [PERMISSION_MICROPHONE] = PERMISSION_POLICY_ONE_TIME,
            [PERMISSION_STORAGE] = PERMISSION_POLICY_DENY,
            [PERMISSION_NOTIFICATIONS] = PERMISSION_POLICY_WHILE_USING,
            [PERMISSION_NETWORK] = PERMISSION_POLICY_WHILE_USING
        },
        .background_access = false
    };
    assert(permission_register_app(&policy));

    struct permission_manifest_policy background_policy = policy;
    background_policy.app_id[0] = 'b';
    background_policy.background_access = true;
    assert(!permission_register_app(&background_policy));

    assert(!permission_process_start(10, "missing.app", false));
    assert(permission_process_start(42, "sample.app", false));
    assert(!permission_process_background_allowed(42));

    struct prompt_test prompt = {
        .choice = PERMISSION_CHOICE_WHILE_USING,
        .choices = 0,
        .calls = 0
    };
    assert(!permission_request(42, PERMISSION_CAMERA, test_prompt, &prompt));
    assert(prompt.calls == 0);
    assert(permission_process_set_foreground(42, true));

    assert(permission_request(42, PERMISSION_CAMERA, test_prompt, &prompt));
    assert(prompt.choices == (PERMISSION_PROMPT_ONLY_THIS_TIME |
                              PERMISSION_PROMPT_WHILE_USING));
    assert(permission_has_grant(42, PERMISSION_CAMERA));
    assert(permission_request(42, PERMISSION_CAMERA, test_prompt, &prompt));
    assert(prompt.calls == 1);

    assert(!permission_process_set_foreground(42, false));
    assert(!permission_has_grant(42, PERMISSION_CAMERA));
    assert(!permission_process_background_allowed(42));

    assert(permission_process_set_foreground(42, true));
    prompt.choice = PERMISSION_CHOICE_WHILE_USING;
    assert(!permission_request(42, PERMISSION_MICROPHONE, test_prompt, &prompt));
    assert(prompt.choices == PERMISSION_PROMPT_ONLY_THIS_TIME);
    prompt.choice = PERMISSION_CHOICE_ONLY_THIS_TIME;
    assert(permission_request(42, PERMISSION_MICROPHONE, test_prompt, &prompt));
    assert(!permission_has_grant(42, PERMISSION_MICROPHONE));
    size_t calls_after_one_time = prompt.calls;
    assert(permission_request(42, PERMISSION_MICROPHONE, test_prompt, &prompt));
    assert(prompt.calls == calls_after_one_time + 1);
    assert(!permission_has_grant(42, PERMISSION_MICROPHONE));

    prompt.choice = PERMISSION_CHOICE_WHILE_USING;
    assert(permission_request(42, PERMISSION_NETWORK, test_prompt, &prompt));

    size_t prompt_calls = prompt.calls;
    assert(!permission_request(42, PERMISSION_STORAGE, test_prompt, &prompt));
    assert(prompt.calls == prompt_calls);

    assert(permission_process_start(1, NULL, true));
    assert(permission_process_background_allowed(1));
    assert(permission_request(1, PERMISSION_STORAGE, NULL, NULL));

    permission_process_exit(42);
    assert(!permission_has_grant(42, PERMISSION_MICROPHONE));
    assert(!permission_process_set_foreground(42, true));

    puts("kernel permission broker tests passed");
    return 0;
}
