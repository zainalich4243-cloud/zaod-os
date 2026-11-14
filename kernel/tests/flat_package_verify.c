#include <stdio.h>
#include <stdlib.h>

#include "exec_zaod.h"
#include "sha256.h"
#include "zaod_format.h"

int main(int argc, char **argv)
{
    if (argc != 3) {
        return 2;
    }
    FILE *package_file = fopen(argv[1], "rb");
    FILE *key_file = fopen(argv[2], "rb");
    if (package_file == NULL || key_file == NULL) {
        return 2;
    }
    if (fseek(package_file, 0, SEEK_END) != 0) {
        return 2;
    }
    long package_size = ftell(package_file);
    if (package_size <= 0 || fseek(package_file, 0, SEEK_SET) != 0) {
        return 2;
    }
    unsigned char *package_bytes = malloc((size_t)package_size);
    unsigned char public_key[ZAOD_ED25519_PUBLIC_KEY_SIZE];
    if (package_bytes == NULL ||
        fread(package_bytes, 1, (size_t)package_size, package_file) !=
            (size_t)package_size ||
        fread(public_key, 1, sizeof(public_key), key_file) !=
            sizeof(public_key) ||
        fgetc(key_file) != EOF) {
        free(package_bytes);
        return 2;
    }

    struct zaod_package_view package;
    struct permission_manifest_policy policy;
    unsigned char manifest_digest[SHA256_DIGEST_SIZE];
    unsigned char elf_digest[SHA256_DIGEST_SIZE];
    int valid = zaod_package_validate_with_key(
        package_bytes, (size_t)package_size, public_key, &package) &&
        zaod_manifest_parse_policy(package.manifest, package.manifest_size,
                                   &policy, manifest_digest);
    if (valid) {
        sha256_digest(package.elf, package.elf_size, elf_digest);
        for (size_t index = 0; index < sizeof(elf_digest); ++index) {
            if (elf_digest[index] != manifest_digest[index]) {
                valid = 0;
                break;
            }
        }
    }
    free(package_bytes);
    fclose(package_file);
    fclose(key_file);
    return valid ? 0 : 1;
}
