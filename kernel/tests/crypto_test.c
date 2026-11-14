#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ed25519.h"
#include "zaod_format.h"

static const zaod_u8 rfc8032_public_key[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

static const zaod_u8 rfc8032_signature[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
};

static const zaod_u8 rfc8032_nonempty_public_key[32] = {
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
    0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
    0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
};

static const zaod_u8 rfc8032_nonempty_signature[64] = {
    0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
    0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
    0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
    0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
    0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
    0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
    0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
    0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
};

/* Test-only package vector; its RFC seed is not a production trust key. */
static const zaod_u8 package_test_public_key[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

static const zaod_u8 package_test_signature[64] = {
    0x82, 0xa1, 0x35, 0xa3, 0x83, 0xd1, 0x36, 0x4e,
    0x47, 0xd6, 0x82, 0x0c, 0x5e, 0x36, 0x3b, 0xce,
    0x37, 0x72, 0x45, 0x49, 0xd6, 0x0c, 0x37, 0x0b,
    0x4d, 0xad, 0x52, 0x76, 0xf9, 0x96, 0xe9, 0xd6,
    0x42, 0xbc, 0x1e, 0xfe, 0x21, 0x32, 0x57, 0x83,
    0xb0, 0x14, 0x1f, 0x75, 0x6f, 0xd4, 0x15, 0x96,
    0x4e, 0x8e, 0x24, 0x13, 0xea, 0x79, 0x35, 0x8a,
    0x6a, 0x79, 0x09, 0xe8, 0x31, 0xa1, 0xb6, 0x0d
};

#define TEST_MANIFEST_OFFSET 88u
#define TEST_MANIFEST_SIZE 2u
#define TEST_ELF_OFFSET (TEST_MANIFEST_OFFSET + TEST_MANIFEST_SIZE)
#define TEST_ELF_SIZE 64u
#define TEST_PACKAGE_SIZE (TEST_ELF_OFFSET + TEST_ELF_SIZE)

static void store_le16(zaod_u8 *destination, uint16_t value)
{
    destination[0] = (zaod_u8)value;
    destination[1] = (zaod_u8)(value >> 8);
}

static void store_le32(zaod_u8 *destination, uint32_t value)
{
    destination[0] = (zaod_u8)value;
    destination[1] = (zaod_u8)(value >> 8);
    destination[2] = (zaod_u8)(value >> 16);
    destination[3] = (zaod_u8)(value >> 24);
}

static void build_package(zaod_u8 package[TEST_PACKAGE_SIZE])
{
    memset(package, 0, TEST_PACKAGE_SIZE);
    memcpy(package, "ZAOD", 4);
    store_le16(package + 4, 1);
    store_le16(package + 6, ZAOD_PACKAGE_HEADER_SIZE);
    store_le32(package + 8, TEST_MANIFEST_OFFSET);
    store_le32(package + 12, TEST_MANIFEST_SIZE);
    store_le32(package + 16, TEST_ELF_OFFSET);
    store_le32(package + 20, TEST_ELF_SIZE);
    memcpy(package + 24, package_test_signature,
           sizeof(package_test_signature));
    memcpy(package + TEST_MANIFEST_OFFSET, "{}", TEST_MANIFEST_SIZE);

    zaod_u8 *elf = package + TEST_ELF_OFFSET;
    elf[0] = 0x7f; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
    elf[4] = 2; elf[5] = 1; elf[6] = 1;
    store_le16(elf + 16, 2);
    store_le16(elf + 18, 62);
    store_le32(elf + 20, 1);
    store_le16(elf + 52, 64);
    store_le16(elf + 54, 56);
}

static void test_ed25519_rfc8032(void)
{
    zaod_u8 altered_signature[sizeof(rfc8032_signature)];
    zaod_u8 noncanonical_signature[sizeof(rfc8032_signature)];
    static const zaod_u8 changed_message[] = {0};
    static const zaod_u8 rfc8032_message[] = {0x72};

    assert(zaod_ed25519_verify(rfc8032_signature, rfc8032_public_key,
                               0, 0));
    assert(zaod_ed25519_verify(rfc8032_nonempty_signature,
                               rfc8032_nonempty_public_key,
                               rfc8032_message, sizeof(rfc8032_message)));
    assert(!zaod_ed25519_verify(rfc8032_signature, rfc8032_public_key,
                                changed_message, sizeof(changed_message)));
    memcpy(altered_signature, rfc8032_signature, sizeof(altered_signature));
    altered_signature[0] ^= 1;
    assert(!zaod_ed25519_verify(altered_signature, rfc8032_public_key,
                                0, 0));
    memcpy(noncanonical_signature, rfc8032_signature,
           sizeof(noncanonical_signature));
    static const zaod_u8 scalar_order[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
    };
    memcpy(noncanonical_signature + 32, scalar_order, sizeof(scalar_order));
    assert(!zaod_ed25519_verify(noncanonical_signature, rfc8032_public_key,
                                0, 0));
    assert(!zaod_ed25519_verify(rfc8032_signature, rfc8032_public_key,
                                changed_message,
                                ZAOD_ED25519_MAX_MESSAGE_SIZE + 1u));
}

static void test_flat_package_parser(void)
{
    zaod_u8 package[TEST_PACKAGE_SIZE];
    struct zaod_package_view view;
    build_package(package);
    assert(zaod_package_validate_with_key(package, sizeof(package),
                                          package_test_public_key, &view));
    assert(view.manifest_size == TEST_MANIFEST_SIZE);
    assert(view.elf_size == TEST_ELF_SIZE);
    assert(memcmp(view.manifest, "{}", TEST_MANIFEST_SIZE) == 0);
    assert(view.elf == package + TEST_ELF_OFFSET);
    assert(!zaod_package_validate_root(package, sizeof(package), &view));

    package[TEST_MANIFEST_OFFSET] ^= 1;
    assert(!zaod_package_validate_with_key(package, sizeof(package),
                                           package_test_public_key, &view));
    build_package(package);
    package[TEST_ELF_OFFSET + 24] ^= 1;
    assert(!zaod_package_validate_with_key(package, sizeof(package),
                                           package_test_public_key, &view));
    build_package(package);
    package[24] ^= 1;
    assert(!zaod_package_validate_with_key(package, sizeof(package),
                                           package_test_public_key, &view));
    build_package(package);
    store_le32(package + 16, TEST_ELF_OFFSET + 1u);
    assert(!zaod_package_validate_with_key(package, sizeof(package),
                                           package_test_public_key, &view));
    assert(!zaod_package_validate_root(package, sizeof(package), &view));
}

int main(void)
{
    test_ed25519_rfc8032();
    test_flat_package_parser();
    puts("kernel Ed25519 and flat package parser tests passed");
    return 0;
}
