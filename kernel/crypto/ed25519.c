/*
 * Ed25519 verification routines derived from TweetNaCl, which is dedicated
 * to the public domain: https://tweetnacl.cr.yp.to/
 *
 * This translation unit intentionally uses no libc, allocation, or platform
 * crypto APIs. The verifier accepts messages no larger than 128 bytes.
 */
#include "ed25519.h"

typedef unsigned long long zaod_u64;
typedef long long zaod_i64;
typedef zaod_i64 zaod_gf[16];

#define FOR(i, n) for ((i) = 0; (i) < (n); ++(i))

static const zaod_gf gf0;
static const zaod_gf gf1 = {1};
static const zaod_gf curve_d = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
static const zaod_gf curve_d2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const zaod_gf base_x = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const zaod_gf base_y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};
static const zaod_gf sqrt_i = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};
static const zaod_u8 group_order[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0x10
};

static const zaod_u64 sha512_constants[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static zaod_u64 rotate_right(zaod_u64 value, unsigned int amount)
{
    return (value >> amount) | (value << (64u - amount));
}

static zaod_u64 load_be64(const zaod_u8 *bytes)
{
    zaod_u64 result = 0;
    for (unsigned int index = 0; index < 8; ++index) {
        result = (result << 8) | bytes[index];
    }
    return result;
}

static void store_be64(zaod_u8 *bytes, zaod_u64 value)
{
    for (int index = 7; index >= 0; --index) {
        bytes[index] = (zaod_u8)value;
        value >>= 8;
    }
}

static void sha512_transform(zaod_u64 state[8], const zaod_u8 block[128])
{
    zaod_u64 words[80];
    zaod_u64 a, b, c, d, e, f, g, h;

    for (unsigned int index = 0; index < 16; ++index) {
        words[index] = load_be64(block + index * 8);
    }
    for (unsigned int index = 16; index < 80; ++index) {
        zaod_u64 s0 = rotate_right(words[index - 15], 1) ^
                      rotate_right(words[index - 15], 8) ^
                      (words[index - 15] >> 7);
        zaod_u64 s1 = rotate_right(words[index - 2], 19) ^
                      rotate_right(words[index - 2], 61) ^
                      (words[index - 2] >> 6);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (unsigned int index = 0; index < 80; ++index) {
        zaod_u64 sum1 = rotate_right(e, 14) ^ rotate_right(e, 18) ^
                        rotate_right(e, 41);
        zaod_u64 choice = (e & f) ^ (~e & g);
        zaod_u64 first = h + sum1 + choice +
                         sha512_constants[index] + words[index];
        zaod_u64 sum0 = rotate_right(a, 28) ^ rotate_right(a, 34) ^
                        rotate_right(a, 39);
        zaod_u64 majority = (a & b) ^ (a & c) ^ (b & c);
        zaod_u64 second = sum0 + majority;
        h = g; g = f; f = e; e = d + first;
        d = c; c = b; b = a; a = first + second;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha512_digest(zaod_u8 output[64], const zaod_u8 *input,
                          zaod_size size)
{
    static const zaod_u64 initial[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    zaod_u64 state[8];
    zaod_u8 final_blocks[256] = {0};
    zaod_size full_blocks = size / 128u;
    zaod_size remainder = size % 128u;
    zaod_size final_size = remainder < 112u ? 128u : 256u;

    for (unsigned int index = 0; index < 8; ++index) {
        state[index] = initial[index];
    }
    for (zaod_size index = 0; index < full_blocks; ++index) {
        sha512_transform(state, input + index * 128u);
    }
    for (zaod_size index = 0; index < remainder; ++index) {
        final_blocks[index] = input[full_blocks * 128u + index];
    }
    final_blocks[remainder] = 0x80;
    store_be64(final_blocks + final_size - 8u, (zaod_u64)size * 8u);
    sha512_transform(state, final_blocks);
    if (final_size == 256u) {
        sha512_transform(state, final_blocks + 128u);
    }
    for (unsigned int index = 0; index < 8; ++index) {
        store_be64(output + index * 8u, state[index]);
    }
}

static int verify_32(const zaod_u8 *left, const zaod_u8 *right)
{
    zaod_u8 difference = 0;
    for (unsigned int index = 0; index < 32; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

static void set25519(zaod_gf result, const zaod_gf input)
{
    for (unsigned int index = 0; index < 16; ++index) {
        result[index] = input[index];
    }
}

static void carry25519(zaod_gf value)
{
    for (unsigned int index = 0; index < 16; ++index) {
        zaod_i64 carry;
        value[index] += (zaod_i64)1 << 16;
        carry = value[index] >> 16;
        value[(index + 1u) * (index < 15u)] +=
            carry - 1 + 37 * (carry - 1) * (index == 15u);
        value[index] -= carry * 65536;
    }
}

static void select25519(zaod_gf left, zaod_gf right, unsigned int choose_right)
{
    zaod_i64 mask = -(zaod_i64)choose_right;
    for (unsigned int index = 0; index < 16; ++index) {
        zaod_i64 value = mask & (left[index] ^ right[index]);
        left[index] ^= value;
        right[index] ^= value;
    }
}

static void pack25519(zaod_u8 output[32], const zaod_gf input)
{
    zaod_gf value, reduced;
    set25519(value, input);
    carry25519(value); carry25519(value); carry25519(value);
    for (unsigned int round = 0; round < 2; ++round) {
        reduced[0] = value[0] - 0xffed;
        for (unsigned int index = 1; index < 15; ++index) {
            reduced[index] = value[index] - 0xffff -
                             ((reduced[index - 1] >> 16) & 1);
            reduced[index - 1] &= 0xffff;
        }
        reduced[15] = value[15] - 0x7fff -
                      ((reduced[14] >> 16) & 1);
        unsigned int borrow = (unsigned int)((reduced[15] >> 16) & 1);
        reduced[14] &= 0xffff;
        select25519(value, reduced, 1u - borrow);
    }
    for (unsigned int index = 0; index < 16; ++index) {
        output[index * 2u] = (zaod_u8)value[index];
        output[index * 2u + 1u] = (zaod_u8)(value[index] >> 8);
    }
}

static int canonical_y(const zaod_u8 encoded[32])
{
    zaod_u8 canonical[32];
    zaod_gf y;
    for (unsigned int index = 0; index < 16; ++index) {
        y[index] = encoded[index * 2u] |
                   ((zaod_i64)encoded[index * 2u + 1u] << 8);
    }
    y[15] &= 0x7fff;
    pack25519(canonical, y);
    canonical[31] |= encoded[31] & 0x80u;
    return verify_32(canonical, encoded);
}

static unsigned int parity25519(const zaod_gf value)
{
    zaod_u8 encoded[32];
    pack25519(encoded, value);
    return encoded[0] & 1u;
}

static void unpack25519(zaod_gf output, const zaod_u8 input[32])
{
    for (unsigned int index = 0; index < 16; ++index) {
        output[index] = input[index * 2u] |
                        ((zaod_i64)input[index * 2u + 1u] << 8);
    }
    output[15] &= 0x7fff;
}

static void add_field(zaod_gf output, const zaod_gf left, const zaod_gf right)
{
    for (unsigned int index = 0; index < 16; ++index) {
        output[index] = left[index] + right[index];
    }
}

static void sub_field(zaod_gf output, const zaod_gf left, const zaod_gf right)
{
    for (unsigned int index = 0; index < 16; ++index) {
        output[index] = left[index] - right[index];
    }
}

static void mul_field(zaod_gf output, const zaod_gf left, const zaod_gf right)
{
    zaod_i64 products[31] = {0};
    for (unsigned int left_index = 0; left_index < 16; ++left_index) {
        for (unsigned int right_index = 0; right_index < 16; ++right_index) {
            products[left_index + right_index] +=
                left[left_index] * right[right_index];
        }
    }
    for (unsigned int index = 0; index < 15; ++index) {
        products[index] += 38 * products[index + 16];
    }
    for (unsigned int index = 0; index < 16; ++index) {
        output[index] = products[index];
    }
    carry25519(output); carry25519(output);
}

static void square_field(zaod_gf output, const zaod_gf input)
{
    mul_field(output, input, input);
}

static void invert25519(zaod_gf output, const zaod_gf input)
{
    zaod_gf value;
    set25519(value, input);
    for (int index = 253; index >= 0; --index) {
        square_field(value, value);
        if (index != 2 && index != 4) {
            mul_field(value, value, input);
        }
    }
    set25519(output, value);
}

static void pow2523(zaod_gf output, const zaod_gf input)
{
    zaod_gf value;
    set25519(value, input);
    for (int index = 250; index >= 0; --index) {
        square_field(value, value);
        if (index != 1) {
            mul_field(value, value, input);
        }
    }
    set25519(output, value);
}

static int equal_field(const zaod_gf left, const zaod_gf right)
{
    zaod_u8 a[32], b[32];
    pack25519(a, left);
    pack25519(b, right);
    return verify_32(a, b);
}

static void point_add(zaod_gf point[4], zaod_gf other[4])
{
    zaod_gf a, b, c, d, t, e, f, g, h;
    sub_field(a, point[1], point[0]);
    sub_field(t, other[1], other[0]);
    mul_field(a, a, t);
    add_field(b, point[0], point[1]);
    add_field(t, other[0], other[1]);
    mul_field(b, b, t);
    mul_field(c, point[3], other[3]);
    mul_field(c, c, curve_d2);
    mul_field(d, point[2], other[2]);
    add_field(d, d, d);
    sub_field(e, b, a); sub_field(f, d, c);
    add_field(g, d, c); add_field(h, b, a);
    mul_field(point[0], e, f);
    mul_field(point[1], h, g);
    mul_field(point[2], g, f);
    mul_field(point[3], e, h);
}

static void point_swap(zaod_gf left[4], zaod_gf right[4], unsigned int choose)
{
    for (unsigned int index = 0; index < 4; ++index) {
        select25519(left[index], right[index], choose);
    }
}

static void point_pack(zaod_u8 output[32], zaod_gf point[4])
{
    zaod_gf x, y, inverse_z;
    invert25519(inverse_z, point[2]);
    mul_field(x, point[0], inverse_z);
    mul_field(y, point[1], inverse_z);
    pack25519(output, y);
    output[31] ^= (zaod_u8)(parity25519(x) << 7);
}

static void point_scalarmult(zaod_gf output[4], zaod_gf point[4],
                             const zaod_u8 scalar[32])
{
    set25519(output[0], gf0);
    set25519(output[1], gf1);
    set25519(output[2], gf1);
    set25519(output[3], gf0);
    for (int bit = 255; bit >= 0; --bit) {
        unsigned int selected =
            (scalar[bit / 8] >> (bit & 7)) & 1u;
        point_swap(output, point, selected);
        point_add(point, output);
        point_add(output, output);
        point_swap(output, point, selected);
    }
}

static void point_scalarbase(zaod_gf output[4], const zaod_u8 scalar[32])
{
    zaod_gf point[4];
    set25519(point[0], base_x);
    set25519(point[1], base_y);
    set25519(point[2], gf1);
    mul_field(point[3], base_x, base_y);
    point_scalarmult(output, point, scalar);
}

static int point_unpack_negative(zaod_gf output[4], const zaod_u8 encoded[32])
{
    zaod_gf numerator, denominator, denominator2, denominator4, denominator6;
    zaod_gf check, root;
    set25519(output[2], gf1);
    unpack25519(output[1], encoded);
    square_field(numerator, output[1]);
    mul_field(denominator, numerator, curve_d);
    sub_field(numerator, numerator, output[2]);
    add_field(denominator, output[2], denominator);
    square_field(denominator2, denominator);
    square_field(denominator4, denominator2);
    mul_field(denominator6, denominator4, denominator2);
    mul_field(root, denominator6, numerator);
    mul_field(root, root, denominator);
    pow2523(root, root);
    mul_field(root, root, numerator);
    mul_field(root, root, denominator);
    mul_field(root, root, denominator);
    mul_field(output[0], root, denominator);
    square_field(check, output[0]);
    mul_field(check, check, denominator);
    if (!equal_field(check, numerator)) {
        mul_field(output[0], output[0], sqrt_i);
    }
    square_field(check, output[0]);
    mul_field(check, check, denominator);
    if (!equal_field(check, numerator)) {
        return -1;
    }
    if (parity25519(output[0]) == (encoded[31] >> 7)) {
        sub_field(output[0], gf0, output[0]);
    }
    mul_field(output[3], output[0], output[1]);
    return 0;
}

static void reduce_scalar(zaod_u8 scalar[64])
{
    static const zaod_u8 order[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
    };
    zaod_i64 values[64];
    for (unsigned int index = 0; index < 64; ++index) {
        values[index] = scalar[index];
        scalar[index] = 0;
    }
    for (int index = 63; index >= 32; --index) {
        zaod_i64 carry = 0;
        int cursor;
        for (cursor = index - 32; cursor < index - 12; ++cursor) {
            values[cursor] += carry - 16 * values[index] *
                              order[cursor - (index - 32)];
            carry = (values[cursor] + 128) >> 8;
            values[cursor] -= carry * 256;
        }
        values[cursor] += carry;
        values[index] = 0;
    }
    zaod_i64 carry = 0;
    for (unsigned int index = 0; index < 32; ++index) {
        values[index] += carry - (values[31] >> 4) * order[index];
        carry = values[index] >> 8;
        values[index] &= 255;
    }
    for (unsigned int index = 0; index < 32; ++index) {
        values[index] -= carry * order[index];
    }
    for (unsigned int index = 0; index < 31; ++index) {
        values[index + 1] += values[index] >> 8;
        scalar[index] = (zaod_u8)values[index];
    }
    scalar[31] = (zaod_u8)values[31];
}

static int scalar_is_canonical(const zaod_u8 scalar[32])
{
    for (int index = 31; index >= 0; --index) {
        if (scalar[index] < group_order[index]) {
            return 1;
        }
        if (scalar[index] > group_order[index]) {
            return 0;
        }
    }
    return 0;
}

static int point_is_small_order(zaod_gf point[4])
{
    zaod_gf doubled[4];
    zaod_u8 encoded[32];
    set25519(doubled[0], point[0]); set25519(doubled[1], point[1]);
    set25519(doubled[2], point[2]); set25519(doubled[3], point[3]);
    for (unsigned int index = 0; index < 3; ++index) {
        point_add(doubled, doubled);
    }
    point_pack(encoded, doubled);
    if (encoded[0] != 1) {
        return 0;
    }
    for (unsigned int index = 1; index < 32; ++index) {
        if (encoded[index] != 0) {
            return 0;
        }
    }
    return 1;
}

int zaod_ed25519_verify(const zaod_u8 signature[64],
                        const zaod_u8 public_key[32],
                        const zaod_u8 *message, zaod_size message_size)
{
    zaod_u8 hash_input[64 + 32 + ZAOD_ED25519_MAX_MESSAGE_SIZE];
    zaod_u8 digest[64], encoded[32];
    zaod_gf public_point[4], result_point[4], signature_point[4];
    zaod_size input_size;

    if (signature == 0 || public_key == 0 ||
        (message == 0 && message_size != 0) ||
        message_size > ZAOD_ED25519_MAX_MESSAGE_SIZE ||
        !scalar_is_canonical(signature + 32) ||
        !canonical_y(public_key) ||
        !canonical_y(signature)) {
        return 0;
    }
    if (point_unpack_negative(public_point, public_key) != 0 ||
        point_is_small_order(public_point)) {
        return 0;
    }

    for (unsigned int index = 0; index < 32; ++index) {
        hash_input[index] = signature[index];
        hash_input[index + 32] = public_key[index];
    }
    for (zaod_size index = 0; index < message_size; ++index) {
        hash_input[index + 64] = message[index];
    }
    input_size = 64u + message_size;
    sha512_digest(digest, hash_input, input_size);
    reduce_scalar(digest);
    point_scalarmult(result_point, public_point, digest);
    point_scalarbase(signature_point, signature + 32);
    point_add(result_point, signature_point);
    point_pack(encoded, result_point);
    return verify_32(signature, encoded);
}
