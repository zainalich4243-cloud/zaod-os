#ifndef ZAOD_FORMAT_H
#define ZAOD_FORMAT_H

#include "../crypto/ed25519.h"

#define ZAOD_PACKAGE_HEADER_SIZE 88u
#define ZAOD_PACKAGE_MAX_MANIFEST_SIZE (64u * 1024u)
#define ZAOD_PACKAGE_MAX_ELF_SIZE (16u * 1024u * 1024u)

struct zaod_package_view {
    const zaod_u8 *manifest;
    zaod_size manifest_size;
    const zaod_u8 *elf;
    zaod_size elf_size;
};

int zaod_package_validate_with_key(
    const zaod_u8 *package, zaod_size package_size,
    const zaod_u8 public_key[ZAOD_ED25519_PUBLIC_KEY_SIZE],
    struct zaod_package_view *view);
int zaod_package_validate_root(const zaod_u8 *package,
                               zaod_size package_size,
                               struct zaod_package_view *view);

#endif
