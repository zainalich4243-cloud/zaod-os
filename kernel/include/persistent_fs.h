#ifndef ZAOD_PERSISTENT_FS_H
#define ZAOD_PERSISTENT_FS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PERSISTENT_FS_SLOT_COUNT 16u
#define PERSISTENT_FS_MAX_FILE_SIZE (2u * 1024u * 1024u)

bool persistent_fs_mount(void);
bool persistent_fs_format(void);
bool persistent_fs_path_allowed(const char *path);
int64_t persistent_fs_open(const char *path, bool create, bool truncate,
                           size_t *slot, size_t *size);
int64_t persistent_fs_read(size_t slot, size_t offset,
                           void *buffer, size_t size);
int64_t persistent_fs_write(size_t slot, size_t offset,
                            const void *buffer, size_t size);
bool persistent_fs_size(size_t slot, size_t *size);

#endif
