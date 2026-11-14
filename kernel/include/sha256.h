#ifndef ZAOD_SHA256_H
#define ZAOD_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32u

struct sha256_context {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t block[64];
    size_t block_size;
};

void sha256_init(struct sha256_context *context);
void sha256_update(struct sha256_context *context,
                   const void *data, size_t size);
void sha256_final(struct sha256_context *context,
                  uint8_t digest[SHA256_DIGEST_SIZE]);
void sha256_digest(const void *data, size_t size,
                   uint8_t digest[SHA256_DIGEST_SIZE]);

#endif
