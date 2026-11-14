#ifndef ZAOD_ZSHIELD_H
#define ZAOD_ZSHIELD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool zshield_verify_trusted_init(const uint8_t *image, size_t image_size);
bool zshield_catalog_ready(void);
bool zshield_digest_is_known(const uint8_t digest[32], const char **label);
bool zshield_scan_bytes(const void *data, size_t size, const char **label);

#endif
