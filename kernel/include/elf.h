#ifndef ZAOD_ELF_H
#define ZAOD_ELF_H

#include <stdbool.h>
#include <stdint.h>

bool elf64_spawn(const char *app_id, bool system_task,
                 const uint8_t *image, size_t image_size, uint64_t *pid);
bool elf64_spawn_verified_app(const char *app_id,
                              const uint8_t *image, size_t image_size,
                              uint64_t *pid);

#endif
