#include "exec_zaod.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../crypto/zaod_keys.h"
#include "../include/elf.h"
#include "../include/permissions.h"
#include "../include/sha256.h"
#include "../include/task.h"
#include "../include/vfs.h"
#include "../include/zshield.h"
#include "zaod_format.h"

#define JSON_TEXT_CAPACITY 256u
#define JSON_ERROR_INVALID 22
#define JSON_ERROR_PERMISSION 13
#define JSON_ERROR_TOO_LARGE 27
#define JSON_ERROR_BUSY 16
#define JSON_ERROR_IO 5

struct json_reader {
    const uint8_t *data;
    size_t size;
    size_t offset;
};

static uint8_t package_buffer[ZAOD_PACKAGE_FILE_MAX]
    __attribute__((aligned(4096)));
static bool package_buffer_busy;

static void json_whitespace(struct json_reader *reader)
{
    while (reader->offset < reader->size) {
        uint8_t value = reader->data[reader->offset];
        if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
            break;
        }
        ++reader->offset;
    }
}

static bool json_take(struct json_reader *reader, uint8_t expected)
{
    json_whitespace(reader);
    if (reader->offset >= reader->size ||
        reader->data[reader->offset] != expected) {
        return false;
    }
    ++reader->offset;
    return true;
}

static bool json_string(struct json_reader *reader, char *output,
                        size_t output_capacity, size_t *output_size)
{
    json_whitespace(reader);
    if (reader->offset >= reader->size ||
        reader->data[reader->offset++] != '"' || output_capacity == 0) {
        return false;
    }
    size_t length = 0;
    while (reader->offset < reader->size) {
        uint8_t value = reader->data[reader->offset++];
        if (value == '"') {
            output[length] = '\0';
            if (output_size != NULL) {
                *output_size = length;
            }
            return true;
        }
        if (value < 0x20 || value > 0x7e || value == '\\' ||
            length + 1 >= output_capacity) {
            return false;
        }
        output[length++] = (char)value;
    }
    return false;
}

static bool json_skip_string(struct json_reader *reader, size_t *length)
{
    json_whitespace(reader);
    if (reader->offset >= reader->size ||
        reader->data[reader->offset++] != '"') {
        return false;
    }
    size_t count = 0;
    while (reader->offset < reader->size) {
        uint8_t value = reader->data[reader->offset++];
        if (value == '"') {
            if (length != NULL) {
                *length = count;
            }
            return true;
        }
        if (value < 0x20) {
            return false;
        }
        if (value == '\\') {
            if (reader->offset >= reader->size) {
                return false;
            }
            value = reader->data[reader->offset++];
            if (value == 'u') {
                for (size_t digit = 0; digit < 4; ++digit) {
                    if (reader->offset >= reader->size) {
                        return false;
                    }
                    uint8_t hex = reader->data[reader->offset++];
                    if (!((hex >= '0' && hex <= '9') ||
                          (hex >= 'a' && hex <= 'f') ||
                          (hex >= 'A' && hex <= 'F'))) {
                        return false;
                    }
                }
            } else if (value != '"' && value != '\\' && value != '/' &&
                       value != 'b' && value != 'f' && value != 'n' &&
                       value != 'r' && value != 't') {
                return false;
            }
        }
        ++count;
    }
    return false;
}

static bool text_equals(const char *left, const char *right)
{
    size_t index = 0;
    while (left[index] != '\0' && left[index] == right[index]) {
        ++index;
    }
    return left[index] == '\0' && right[index] == '\0';
}

static bool safe_package_file_path(const char *path)
{
    if (path[0] == '\0' || path[0] == '/') {
        return false;
    }
    size_t segment_start = 0;
    for (size_t index = 0; path[index] != '\0'; ++index) {
        char value = path[index];
        if (value == '\\' ||
            !((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') ||
              value == '_' || value == '-' || value == '.' ||
              value == '/')) {
            return false;
        }
        if (value == '/') {
            size_t segment_size = index - segment_start;
            if (segment_size == 0 ||
                (segment_size == 1 && path[segment_start] == '.') ||
                (segment_size == 2 && path[segment_start] == '.' &&
                 path[segment_start + 1] == '.')) {
                return false;
            }
            segment_start = index + 1;
        }
    }
    size_t final_segment_size = 0;
    while (path[segment_start + final_segment_size] != '\0') {
        ++final_segment_size;
    }
    return final_segment_size != 0 &&
           !(final_segment_size == 1 && path[segment_start] == '.') &&
           !(final_segment_size == 2 && path[segment_start] == '.' &&
             path[segment_start + 1] == '.');
}

static bool json_uint(struct json_reader *reader, uint32_t expected)
{
    json_whitespace(reader);
    if (reader->offset >= reader->size) {
        return false;
    }
    uint32_t value = 0;
    size_t start = reader->offset;
    while (reader->offset < reader->size) {
        uint8_t digit = reader->data[reader->offset];
        if (digit < '0' || digit > '9') {
            break;
        }
        if (value > (UINT32_MAX - (digit - '0')) / 10u) {
            return false;
        }
        value = value * 10u + digit - '0';
        ++reader->offset;
    }
    return reader->offset != start &&
           (reader->offset - start == 1 || reader->data[start] != '0') &&
           value == expected;
}

static bool json_literal(struct json_reader *reader, const char *literal)
{
    json_whitespace(reader);
    size_t index = 0;
    while (literal[index] != '\0') {
        if (reader->offset >= reader->size ||
            reader->data[reader->offset++] != (uint8_t)literal[index]) {
            return false;
        }
        ++index;
    }
    return true;
}

static bool parse_policy_level(struct json_reader *reader,
                               enum permission_policy_level *level)
{
    char value[32];
    if (!json_string(reader, value, sizeof(value), NULL)) {
        return false;
    }
    if (text_equals(value, "deny") || text_equals(value, "none")) {
        *level = PERMISSION_POLICY_DENY;
    } else if (text_equals(value, "one-time")) {
        *level = PERMISSION_POLICY_ONE_TIME;
    } else if (text_equals(value, "while-using") ||
               text_equals(value, "foreground")) {
        *level = PERMISSION_POLICY_WHILE_USING;
    } else {
        return false;
    }
    return true;
}

static bool parse_permissions(struct json_reader *reader,
                              struct permission_manifest_policy *policy)
{
    static const char *const keys[6] = {
        "camera", "microphone", "storage", "notifications", "network",
        "background"
    };
    bool seen[6] = {false};
    if (!json_take(reader, '{')) {
        return false;
    }
    json_whitespace(reader);
    if (reader->offset < reader->size &&
        reader->data[reader->offset] == '}') {
        return false;
    }

    for (size_t field = 0; field < 6; ++field) {
        char key[32];
        if (!json_string(reader, key, sizeof(key), NULL) ||
            !json_take(reader, ':')) {
            return false;
        }
        size_t key_index = 0;
        while (key_index < 6 && !text_equals(key, keys[key_index])) {
            ++key_index;
        }
        if (key_index == 6 || seen[key_index]) {
            return false;
        }
        seen[key_index] = true;
        if (key_index == 5) {
            if (!json_literal(reader, "false")) {
                return false;
            }
            policy->background_access = false;
        } else {
            enum permission_policy_level level;
            if (!parse_policy_level(reader, &level)) {
                return false;
            }
            enum permission_resource resource =
                key_index == 0 ? PERMISSION_CAMERA :
                key_index == 1 ? PERMISSION_MICROPHONE :
                key_index == 2 ? PERMISSION_STORAGE :
                key_index == 3 ? PERMISSION_NOTIFICATIONS :
                                 PERMISSION_NETWORK;
            if (resource == PERMISSION_NETWORK &&
                level == PERMISSION_POLICY_ONE_TIME) {
                return false;
            }
            policy->resources[resource] = level;
        }
        json_whitespace(reader);
        if (field != 5 && !json_take(reader, ',')) {
            return false;
        }
    }
    return json_take(reader, '}');
}

static bool parse_binary_digest(struct json_reader *reader,
                                uint8_t digest[SHA256_DIGEST_SIZE])
{
    char hex[SHA256_DIGEST_SIZE * 2u + 1u];
    size_t hex_size = 0;
    if (!json_string(reader, hex, sizeof(hex), &hex_size) ||
        hex_size != SHA256_DIGEST_SIZE * 2u) {
        return false;
    }
    for (size_t index = 0; index < SHA256_DIGEST_SIZE; ++index) {
        uint8_t high = (uint8_t)hex[index * 2u];
        uint8_t low = (uint8_t)hex[index * 2u + 1u];
        if (high < '0' || high > '9') {
            if (high < 'a' || high > 'f') {
                return false;
            }
            high = (uint8_t)(high - 'a' + 10);
        } else {
            high = (uint8_t)(high - '0');
        }
        if (low < '0' || low > '9') {
            if (low < 'a' || low > 'f') {
                return false;
            }
            low = (uint8_t)(low - 'a' + 10);
        } else {
            low = (uint8_t)(low - '0');
        }
        digest[index] = (uint8_t)((high << 4) | low);
    }
    return hex[SHA256_DIGEST_SIZE * 2u] == '\0';
}

static bool parse_files(struct json_reader *reader,
                        uint8_t binary_digest[SHA256_DIGEST_SIZE])
{
    if (!json_take(reader, '{')) {
        return false;
    }
    size_t file_count = 0;
    bool found_entrypoint = false;
    do {
        char path[JSON_TEXT_CAPACITY];
        uint8_t digest[SHA256_DIGEST_SIZE];
        if (++file_count > 128 ||
            !json_string(reader, path, sizeof(path), NULL) ||
            !safe_package_file_path(path) ||
            !json_take(reader, ':') ||
            !parse_binary_digest(reader, digest)) {
            return false;
        }
        if (text_equals(path, "bin/app")) {
            if (found_entrypoint) {
                return false;
            }
            found_entrypoint = true;
            for (size_t index = 0; index < SHA256_DIGEST_SIZE; ++index) {
                binary_digest[index] = digest[index];
            }
        }
        json_whitespace(reader);
        if (reader->offset >= reader->size) {
            return false;
        }
        if (reader->data[reader->offset] == '}') {
            break;
        }
        if (!json_take(reader, ',')) {
            return false;
        }
    } while (true);
    return found_entrypoint && json_take(reader, '}');
}

bool zaod_manifest_parse_policy(const uint8_t *manifest, size_t manifest_size,
                                struct permission_manifest_policy *policy,
                                uint8_t binary_sha256[32])
{
    enum manifest_field {
        MANIFEST_SCHEMA = 1u << 0,
        MANIFEST_APP_ID = 1u << 1,
        MANIFEST_VERSION = 1u << 2,
        MANIFEST_AUTHOR = 1u << 3,
        MANIFEST_ENTRYPOINT = 1u << 4,
        MANIFEST_PERMISSIONS = 1u << 5,
        MANIFEST_FILES = 1u << 6,
        MANIFEST_ALL = (1u << 7) - 1u
    };
    if (manifest == NULL || policy == NULL || binary_sha256 == NULL ||
        manifest_size == 0 || manifest_size > ZAOD_PACKAGE_MAX_MANIFEST_SIZE) {
        return false;
    }
    struct permission_manifest_policy parsed = {0};
    char app_id[PERMISSION_APP_ID_CAPACITY] = {0};
    char entrypoint[JSON_TEXT_CAPACITY] = {0};
    uint8_t file_digest[SHA256_DIGEST_SIZE] = {0};
    uint32_t fields = 0;
    struct json_reader reader = {
        .data = manifest,
        .size = manifest_size,
        .offset = 0
    };
    if (!json_take(&reader, '{')) {
        return false;
    }
    json_whitespace(&reader);
    while (reader.offset < reader.size &&
           reader.data[reader.offset] != '}') {
        char key[32];
        if (!json_string(&reader, key, sizeof(key), NULL) ||
            !json_take(&reader, ':')) {
            return false;
        }
        uint32_t bit;
        if (text_equals(key, "schema_version")) {
            bit = MANIFEST_SCHEMA;
            if (!json_uint(&reader, 2)) {
                return false;
            }
        } else if (text_equals(key, "app_id")) {
            bit = MANIFEST_APP_ID;
            if (!json_string(&reader, app_id, sizeof(app_id), NULL)) {
                return false;
            }
        } else if (text_equals(key, "version")) {
            char value[64];
            bit = MANIFEST_VERSION;
            if (!json_string(&reader, value, sizeof(value), NULL) ||
                value[0] == '\0') {
                return false;
            }
        } else if (text_equals(key, "author")) {
            size_t value_length = 0;
            bit = MANIFEST_AUTHOR;
            if (!json_skip_string(&reader, &value_length) ||
                value_length == 0) {
                return false;
            }
        } else if (text_equals(key, "entrypoint")) {
            bit = MANIFEST_ENTRYPOINT;
            if (!json_string(&reader, entrypoint, sizeof(entrypoint), NULL)) {
                return false;
            }
        } else if (text_equals(key, "permissions")) {
            bit = MANIFEST_PERMISSIONS;
            if (!parse_permissions(&reader, &parsed)) {
                return false;
            }
        } else if (text_equals(key, "files")) {
            bit = MANIFEST_FILES;
            if (!parse_files(&reader, file_digest)) {
                return false;
            }
        } else {
            return false;
        }
        if ((fields & bit) != 0) {
            return false;
        }
        fields |= bit;
        json_whitespace(&reader);
        if (reader.offset < reader.size &&
            reader.data[reader.offset] == '}') {
            break;
        }
        if (!json_take(&reader, ',')) {
            return false;
        }
    }
    if (!json_take(&reader, '}')) {
        return false;
    }
    json_whitespace(&reader);
    if (reader.offset != reader.size || fields != MANIFEST_ALL ||
        !text_equals(entrypoint, "bin/app") || parsed.background_access) {
        return false;
    }
    size_t app_id_length = 0;
    while (app_id[app_id_length] != '\0' &&
           app_id_length < PERMISSION_APP_ID_CAPACITY) {
        char value = app_id[app_id_length];
        if (!((value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') ||
              value == '.' || value == '-')) {
            return false;
        }
        ++app_id_length;
    }
    if (app_id_length == 0 || app_id_length >= PERMISSION_APP_ID_CAPACITY ||
        app_id[0] == '.' || app_id[app_id_length - 1] == '.' ||
        app_id[app_id_length - 1] == '-') {
        return false;
    }
    for (size_t index = 0; index <= app_id_length; ++index) {
        parsed.app_id[index] = app_id[index];
    }
    *policy = parsed;
    for (size_t index = 0; index < SHA256_DIGEST_SIZE; ++index) {
        binary_sha256[index] = file_digest[index];
    }
    return true;
}

static bool path_is_zaod_package(const char *path)
{
    if (path == NULL || path[0] != '/') {
        return false;
    }
    size_t length = 0;
    while (path[length] != '\0' && length < 256u) {
        ++length;
    }
    return length > 6u && length < 256u &&
           path[length - 6u] == '.' && path[length - 5u] == 'z' &&
           path[length - 4u] == 'a' && path[length - 3u] == 'o' &&
           path[length - 2u] == 'd' && path[length - 1u] == '\0';
}

static bool package_app_path_matches(const char *path, const char *app_id)
{
    static const char prefix[] = "/opt/zaod/apps/";
    size_t path_length = 0;
    while (path[path_length] != '\0' && path_length < 256u) {
        ++path_length;
    }
    if (path_length >= 256u) {
        return false;
    }
    size_t index = 0;
    while (prefix[index] != '\0') {
        if (path[index] != prefix[index]) {
            return false;
        }
        ++index;
    }
    size_t app_index = 0;
    while (app_id[app_index] != '\0') {
        if (app_index >= 64u) {
            return false;
        }
        if (index + app_index >= path_length) {
            return false;
        }
        if (path[index + app_index] != app_id[app_index]) {
            return false;
        }
        ++app_index;
    }
    return app_index != 0 && path_length < 256u &&
           path_length > index + app_index &&
           path[index + app_index] == '/';
}

int64_t zaod_exec_package_path(const char *path, uint64_t *child_pid)
{
    if (!path_is_zaod_package(path) || child_pid == NULL) {
        return -JSON_ERROR_INVALID;
    }
    if (!task_current_is_system() || task_non_system_active_count() != 0) {
        return -JSON_ERROR_PERMISSION;
    }
    if (package_buffer_busy) {
        return -JSON_ERROR_BUSY;
    }
    package_buffer_busy = true;
    int64_t descriptor = vfs_open(path, VFS_OPEN_READ);
    if (descriptor < 0) {
        package_buffer_busy = false;
        return descriptor;
    }
    size_t package_size = 0;
    int64_t result = 0;
    while (package_size < sizeof(package_buffer)) {
        size_t amount = sizeof(package_buffer) - package_size;
        if (amount > 4096u) {
            amount = 4096u;
        }
        int64_t read = vfs_read(descriptor, package_buffer + package_size,
                                amount);
        if (read < 0) {
            result = read;
            goto cleanup;
        }
        if (read == 0) {
            break;
        }
        package_size += (size_t)read;
    }
    if (package_size == sizeof(package_buffer)) {
        uint8_t extra;
        int64_t read = vfs_read(descriptor, &extra, 1);
        if (read != 0) {
            result = read < 0 ? read : -JSON_ERROR_TOO_LARGE;
            goto cleanup;
        }
    }

    struct zaod_package_view package;
    struct permission_manifest_policy policy;
    uint8_t expected_binary_hash[SHA256_DIGEST_SIZE];
    uint8_t actual_binary_hash[SHA256_DIGEST_SIZE];
    if (!zaod_package_validate_root(package_buffer, package_size, &package) ||
        !zaod_manifest_parse_policy(package.manifest, package.manifest_size,
                                    &policy, expected_binary_hash)) {
        result = -JSON_ERROR_PERMISSION;
        goto cleanup;
    }
    sha256_digest(package.elf, package.elf_size, actual_binary_hash);
    uint8_t hash_difference = 0;
    for (size_t index = 0; index < SHA256_DIGEST_SIZE; ++index) {
        hash_difference |= expected_binary_hash[index] ^ actual_binary_hash[index];
    }
    if (hash_difference != 0 || !zshield_catalog_ready() ||
        zshield_digest_is_known(actual_binary_hash, NULL)) {
        result = -JSON_ERROR_PERMISSION;
        goto cleanup;
    }
    if (!package_app_path_matches(path, policy.app_id)) {
        result = -JSON_ERROR_PERMISSION;
        goto cleanup;
    }
    if (!permission_register_app(&policy)) {
        result = -JSON_ERROR_PERMISSION;
        goto cleanup;
    }
    if (!elf64_spawn_verified_app(policy.app_id, package.elf,
                                  package.elf_size, child_pid)) {
        result = -JSON_ERROR_PERMISSION;
        goto cleanup;
    }
    result = (int64_t)*child_pid;

cleanup:
    (void)vfs_close(descriptor);
    package_buffer_busy = false;
    return result;
}
