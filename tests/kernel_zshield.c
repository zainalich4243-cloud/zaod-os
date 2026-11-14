#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"
#include "zshield.h"

static void assert_digest(const uint8_t *actual, const char *expected_hex)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < SHA256_DIGEST_SIZE; ++index) {
        assert(digits[actual[index] >> 4] == expected_hex[index * 2]);
        assert(digits[actual[index] & 15] == expected_hex[index * 2 + 1]);
    }
}

int main(void)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_digest("", 0, digest);
    assert_digest(digest,
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855");
    sha256_digest("abc", 3, digest);
    assert_digest(digest,
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad");

    FILE *init = fopen("../build/user/init.elf", "rb");
    assert(init != NULL);
    uint8_t image[1024 * 1024];
    size_t size = fread(image, 1, sizeof(image), init);
    assert(!ferror(init));
    assert(feof(init));
    assert(fclose(init) == 0);
    assert(zshield_verify_trusted_init(image, size));
    image[size / 2] ^= 1;
    assert(!zshield_verify_trusted_init(image, size));
    assert(!zshield_verify_trusted_init(NULL, 1));
    assert(!zshield_verify_trusted_init(image, 0));
    puts("kernel SHA-256 and trusted-image gate tests passed");
    return 0;
}
