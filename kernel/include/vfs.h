#ifndef ZAOD_VFS_H
#define ZAOD_VFS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VFS_OPEN_READ 0x1u
#define VFS_OPEN_WRITE 0x2u
#define VFS_OPEN_CREATE 0x4u
#define VFS_OPEN_TRUNCATE 0x8u

bool vfs_init(const void *initramfs, size_t size);
bool vfs_kernel_file(const char *path, const uint8_t **data, size_t *size);
int64_t vfs_open(const char *path, uint32_t flags);
int64_t vfs_read(int64_t descriptor, void *buffer, size_t size);
int64_t vfs_write(int64_t descriptor, const void *buffer, size_t size);
void vfs_close(int64_t descriptor);
void vfs_close_process(uint64_t pid);

#endif
