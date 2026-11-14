#ifndef ZAOD_EXEC_ZAOD_H
#define ZAOD_EXEC_ZAOD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../include/permissions.h"

#define ZAOD_APP_ID_MAX 64u
#define ZAOD_PACKAGE_FILE_MAX (2u * 1024u * 1024u)

bool zaod_manifest_parse_policy(const uint8_t *manifest, size_t manifest_size,
                                struct permission_manifest_policy *policy,
                                uint8_t binary_sha256[32]);
int64_t zaod_exec_package_path(const char *path, uint64_t *child_pid);

#endif
