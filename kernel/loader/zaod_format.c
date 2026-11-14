#include "zaod_format.h"

#include "../crypto/zaod_keys.h"
#include "../include/sha256.h"

#define ZAOD_FORMAT_VERSION 1u
#define ZAOD_SIGNATURE_OFFSET 24u
#define ZAOD_SIGNATURE_END (ZAOD_SIGNATURE_OFFSET + 64u)

static zaod_u16 load_le16(const zaod_u8 *bytes)
{
    return (zaod_u16)(bytes[0] | ((zaod_u16)bytes[1] << 8));
}

static zaod_u32 load_le32(const zaod_u8 *bytes)
{
    return (zaod_u32)bytes[0] |
           ((zaod_u32)bytes[1] << 8) |
           ((zaod_u32)bytes[2] << 16) |
           ((zaod_u32)bytes[3] << 24);
}

static void store_le32(zaod_u8 *bytes, zaod_u32 value)
{
    bytes[0] = (zaod_u8)value;
    bytes[1] = (zaod_u8)(value >> 8);
    bytes[2] = (zaod_u8)(value >> 16);
    bytes[3] = (zaod_u8)(value >> 24);
}

static int range_valid(zaod_size offset, zaod_size length,
                       zaod_size package_size)
{
    return offset <= package_size && length <= package_size - offset;
}

static int elf64_x86_64(const zaod_u8 *elf, zaod_size size)
{
    return size >= 64u &&
           elf[0] == 0x7f && elf[1] == 'E' && elf[2] == 'L' && elf[3] == 'F' &&
           elf[4] == 2 && elf[5] == 1 && elf[6] == 1 &&
           elf[16] == 2 && elf[17] == 0 &&
           elf[18] == 62 && elf[19] == 0 &&
           elf[20] == 1 && elf[21] == 0 && elf[22] == 0 && elf[23] == 0 &&
           load_le16(elf + 52) == 64u &&
           load_le16(elf + 54) == 56u;
}

int zaod_package_validate_with_key(
    const zaod_u8 *package, zaod_size package_size,
    const zaod_u8 public_key[ZAOD_ED25519_PUBLIC_KEY_SIZE],
    struct zaod_package_view *view)
{
    static const zaod_u8 domain[] = {
        'Z', 'A', 'O', 'D', '-', 'F', 'L', 'A', 'T', '-', 'P', 'K', 'G',
        '-', 'V', '1', 0
    };
    zaod_u8 manifest_hash[SHA256_DIGEST_SIZE];
    zaod_u8 elf_hash[SHA256_DIGEST_SIZE];
    zaod_u8 signed_message[sizeof(domain) + 8u +
                           2u * SHA256_DIGEST_SIZE];

    if (package == 0 || public_key == 0 || view == 0 ||
        package_size < ZAOD_PACKAGE_HEADER_SIZE ||
        package[0] != 'Z' || package[1] != 'A' ||
        package[2] != 'O' || package[3] != 'D' ||
        load_le16(package + 4) != ZAOD_FORMAT_VERSION ||
        load_le16(package + 6) != ZAOD_PACKAGE_HEADER_SIZE) {
        return 0;
    }

    zaod_u32 manifest_offset = load_le32(package + 8);
    zaod_u32 manifest_size = load_le32(package + 12);
    zaod_u32 elf_offset = load_le32(package + 16);
    zaod_u32 elf_size = load_le32(package + 20);
    if (manifest_offset != ZAOD_PACKAGE_HEADER_SIZE ||
        manifest_size == 0 ||
        manifest_size > ZAOD_PACKAGE_MAX_MANIFEST_SIZE ||
        elf_offset != manifest_offset + manifest_size ||
        elf_size < 64u || elf_size > ZAOD_PACKAGE_MAX_ELF_SIZE ||
        !range_valid(manifest_offset, manifest_size, package_size) ||
        !range_valid(elf_offset, elf_size, package_size) ||
        (zaod_size)elf_offset + elf_size != package_size ||
        !elf64_x86_64(package + elf_offset, elf_size)) {
        return 0;
    }

    sha256_digest(package + manifest_offset, manifest_size, manifest_hash);
    sha256_digest(package + elf_offset, elf_size, elf_hash);

    zaod_size cursor = 0;
    for (zaod_size index = 0; index < sizeof(domain); ++index) {
        signed_message[cursor++] = domain[index];
    }
    store_le32(signed_message + cursor, manifest_size);
    cursor += 4;
    store_le32(signed_message + cursor, elf_size);
    cursor += 4;
    for (zaod_size index = 0; index < SHA256_DIGEST_SIZE; ++index) {
        signed_message[cursor++] = manifest_hash[index];
    }
    for (zaod_size index = 0; index < SHA256_DIGEST_SIZE; ++index) {
        signed_message[cursor++] = elf_hash[index];
    }
    if (cursor != sizeof(signed_message) ||
        !zaod_ed25519_verify(package + ZAOD_SIGNATURE_OFFSET, public_key,
                             signed_message, cursor)) {
        return 0;
    }

    view->manifest = package + manifest_offset;
    view->manifest_size = manifest_size;
    view->elf = package + elf_offset;
    view->elf_size = elf_size;
    return 1;
}

int zaod_package_validate_root(const zaod_u8 *package,
                               zaod_size package_size,
                               struct zaod_package_view *view)
{
#if ZAOD_ROOT_PUBLIC_KEY_CONFIGURED
    return zaod_package_validate_with_key(
        package, package_size, ZAOD_ROOT_PUBLIC_KEY, view);
#else
    (void)package;
    (void)package_size;
    (void)view;
    return 0;
#endif
}
