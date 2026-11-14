#ifndef ZAOD_CHACHA20_H
#define ZAOD_CHACHA20_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZAOD_CHACHA20_KEY_SIZE 32u
#define ZAOD_CHACHA20_NONCE_SIZE 12u
#define ZAOD_POLY1305_TAG_SIZE 16u

/* The caller must never reuse a key/nonce pair. Exact in-place operation is supported. */
bool zaod_chacha20poly1305_encrypt(
    const uint8_t key[ZAOD_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ZAOD_CHACHA20_NONCE_SIZE],
    const void *associated_data, size_t associated_data_size,
    const void *plaintext, size_t plaintext_size,
    void *ciphertext, uint8_t tag[ZAOD_POLY1305_TAG_SIZE]);
bool zaod_chacha20poly1305_decrypt(
    const uint8_t key[ZAOD_CHACHA20_KEY_SIZE],
    const uint8_t nonce[ZAOD_CHACHA20_NONCE_SIZE],
    const void *associated_data, size_t associated_data_size,
    const void *ciphertext, size_t ciphertext_size,
    const uint8_t tag[ZAOD_POLY1305_TAG_SIZE], void *plaintext);

#endif
