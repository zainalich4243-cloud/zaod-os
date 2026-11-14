#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "exec_zaod.h"

static const char valid_manifest[] =
    "{\"app_id\":\"org.zaod.demo\",\"author\":\"ZAOD Test\","
    "\"entrypoint\":\"bin/app\",\"files\":{"
    "\"assets/icon.svg\":\"0000000000000000000000000000000000000000000000000000000000000000\","
    "\"bin/app\":\"abababababababababababababababababababababababababababababababab\"},"
    "\"permissions\":{\"background\":false,\"camera\":\"one-time\","
    "\"microphone\":\"deny\",\"network\":\"foreground\","
    "\"notifications\":\"deny\",\"storage\":\"while-using\"},"
    "\"schema_version\":2,\"version\":\"1.0.0\"}";

int main(void)
{
    struct permission_manifest_policy policy = {0};
    uint8_t digest[32] = {0};
    assert(zaod_manifest_parse_policy(
        (const uint8_t *)valid_manifest, sizeof(valid_manifest) - 1,
        &policy, digest));
    assert(strcmp(policy.app_id, "org.zaod.demo") == 0);
    assert(policy.resources[PERMISSION_CAMERA] ==
           PERMISSION_POLICY_ONE_TIME);
    assert(policy.resources[PERMISSION_NETWORK] ==
           PERMISSION_POLICY_WHILE_USING);
    assert(policy.resources[PERMISSION_STORAGE] ==
           PERMISSION_POLICY_WHILE_USING);
    assert(!policy.background_access);
    for (size_t index = 0; index < sizeof(digest); ++index) {
        assert(digest[index] == 0xab);
    }

    char unsafe_background[sizeof(valid_manifest)];
    memcpy(unsafe_background, valid_manifest, sizeof(valid_manifest));
    char *background = strstr(unsafe_background, "\"background\":false");
    assert(background != NULL);
    memcpy(background, "\"background\":true ", 18);
    assert(!zaod_manifest_parse_policy(
        (const uint8_t *)unsafe_background,
        sizeof(unsafe_background) - 1, &policy, digest));

    static const char duplicate_key[] =
        "{\"app_id\":\"org.zaod.demo\",\"app_id\":\"org.zaod.evil\","
        "\"author\":\"ZAOD Test\",\"entrypoint\":\"bin/app\","
        "\"files\":{\"bin/app\":\"abababababababababababababababababababababababababababababababab\"},"
        "\"permissions\":{\"background\":false,\"camera\":\"deny\","
        "\"microphone\":\"deny\",\"network\":\"none\","
        "\"notifications\":\"deny\",\"storage\":\"deny\"},"
        "\"schema_version\":2,\"version\":\"1.0.0\"}";
    assert(!zaod_manifest_parse_policy(
        (const uint8_t *)duplicate_key, sizeof(duplicate_key) - 1,
        &policy, digest));

    puts("ZAOD manifest policy tests passed");
    return 0;
}
