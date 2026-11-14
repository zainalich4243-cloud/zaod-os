#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "chacha20.h"

static void decode_hex(const char *text, uint8_t *output, size_t output_size)
{
    for (size_t index = 0; index < output_size; ++index) {
        char high = text[index * 2];
        char low = text[index * 2 + 1];
        uint8_t high_value = high >= '0' && high <= '9'
            ? (uint8_t)(high - '0')
            : (uint8_t)(high - 'a' + 10);
        uint8_t low_value = low >= '0' && low <= '9'
            ? (uint8_t)(low - '0')
            : (uint8_t)(low - 'a' + 10);
        output[index] = (uint8_t)((high_value << 4) | low_value);
    }
}

int main(void)
{
    static const char plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    static const char expected_ciphertext_hex[] =
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116";
    static const char expected_tag_hex[] =
        "1ae10b594f09e26a7e902ecbd0600691";
    uint8_t key[ZAOD_CHACHA20_KEY_SIZE];
    uint8_t nonce[ZAOD_CHACHA20_NONCE_SIZE];
    uint8_t associated_data[12];
    uint8_t expected_ciphertext[sizeof(plaintext) - 1];
    uint8_t expected_tag[ZAOD_POLY1305_TAG_SIZE];
    uint8_t ciphertext[sizeof(plaintext) - 1];
    uint8_t decrypted[sizeof(plaintext) - 1];
    uint8_t altered_tag[ZAOD_POLY1305_TAG_SIZE];

    for (size_t index = 0; index < sizeof(key); ++index) {
        key[index] = (uint8_t)(0x80 + index);
    }
    decode_hex("070000004041424344454647", nonce, sizeof(nonce));
    decode_hex("50515253c0c1c2c3c4c5c6c7",
               associated_data, sizeof(associated_data));
    decode_hex(expected_ciphertext_hex, expected_ciphertext,
               sizeof(expected_ciphertext));
    decode_hex(expected_tag_hex, expected_tag, sizeof(expected_tag));

    assert(zaod_chacha20poly1305_encrypt(
        key, nonce, associated_data, sizeof(associated_data),
        plaintext, sizeof(plaintext) - 1, ciphertext, altered_tag));
    assert(memcmp(ciphertext, expected_ciphertext,
                  sizeof(ciphertext)) == 0);
    assert(memcmp(altered_tag, expected_tag, sizeof(altered_tag)) == 0);
    assert(zaod_chacha20poly1305_decrypt(
        key, nonce, associated_data, sizeof(associated_data),
        ciphertext, sizeof(ciphertext), expected_tag, decrypted));
    assert(memcmp(decrypted, plaintext, sizeof(decrypted)) == 0);

    memcpy(altered_tag, expected_tag, sizeof(altered_tag));
    altered_tag[0] ^= 1;
    memset(decrypted, 0xa5, sizeof(decrypted));
    assert(!zaod_chacha20poly1305_decrypt(
        key, nonce, associated_data, sizeof(associated_data),
        ciphertext, sizeof(ciphertext), altered_tag, decrypted));
    for (size_t index = 0; index < sizeof(decrypted); ++index) {
        assert(decrypted[index] == 0xa5);
    }

    puts("ChaCha20-Poly1305 RFC 8439 tests passed");
    return 0;
}
