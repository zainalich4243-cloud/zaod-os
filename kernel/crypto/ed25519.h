#ifndef ZAOD_ED25519_H
#define ZAOD_ED25519_H

typedef unsigned char zaod_u8;
typedef unsigned short zaod_u16;
typedef unsigned int zaod_u32;
typedef unsigned long zaod_size;

#define ZAOD_ED25519_PUBLIC_KEY_SIZE 32u
#define ZAOD_ED25519_SIGNATURE_SIZE 64u
#define ZAOD_ED25519_MAX_MESSAGE_SIZE 128u

int zaod_ed25519_verify(const zaod_u8 signature[ZAOD_ED25519_SIGNATURE_SIZE],
                        const zaod_u8 public_key[ZAOD_ED25519_PUBLIC_KEY_SIZE],
                        const zaod_u8 *message, zaod_size message_size);

#endif
