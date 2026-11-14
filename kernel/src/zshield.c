#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sha256.h"
#include "zshield.h"
#include "trusted_init_hash.h"

struct zshield_hash_definition {
    uint8_t digest[SHA256_DIGEST_SIZE];
    const char *label;
};

#include "zshield_hashes.h"

static const uint8_t trusted_init_sha256[SHA256_DIGEST_SIZE] =
    ZAOD_TRUSTED_INIT_SHA256;
static const struct zshield_hash_definition definitions[] =
    ZAOD_ZSHIELD_DEFINITION_INITIALIZERS;

bool zshield_verify_trusted_init(const uint8_t *image, size_t image_size)
{
    if (image == NULL || image_size == 0) {
        return false;
    }
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_digest(image, image_size, digest);
    uint8_t difference = 0;
    for (size_t index = 0; index < sizeof(digest); ++index) {
        difference |= digest[index] ^ trusted_init_sha256[index];
    }
    return difference == 0;
}

bool zshield_catalog_ready(void)
{
    return ZAOD_ZSHIELD_CATALOG_AUTHENTICATED != 0;
}

bool zshield_digest_is_known(const uint8_t digest[SHA256_DIGEST_SIZE],
                             const char **label)
{
    if (digest == NULL) {
        return false;
    }
    size_t low = 0;
    size_t high = ZAOD_ZSHIELD_DEFINITION_COUNT;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int comparison = 0;
        for (size_t byte_index = 0;
             byte_index < SHA256_DIGEST_SIZE;
             ++byte_index) {
            if (digest[byte_index] < definitions[middle].digest[byte_index]) {
                comparison = -1;
                break;
            }
            if (digest[byte_index] > definitions[middle].digest[byte_index]) {
                comparison = 1;
                break;
            }
        }
        if (comparison == 0) {
            if (label != NULL) {
                *label = definitions[middle].label;
            }
            return true;
        }
        if (comparison < 0) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    return false;
}

bool zshield_scan_bytes(const void *data, size_t size, const char **label)
{
    if (data == NULL && size != 0) {
        return false;
    }
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_digest(data, size, digest);
    return zshield_digest_is_known(digest, label);
}
