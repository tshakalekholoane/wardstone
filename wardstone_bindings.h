#ifndef WARDSTONE_BINDINGS_H
#define WARDSTONE_BINDINGS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Hash {
  uint16_t _0;
} Hash;

typedef struct Symmetric {
  uint16_t _0;
} Symmetric;

extern const struct Hash BLAKE2b_256;

extern const struct Hash BLAKE2b_384;

extern const struct Hash BLAKE2b_512;

extern const struct Hash BLAKE2s_256;

extern const struct Hash MD4;

extern const struct Hash MD5;

extern const struct Hash RIPEMD160;

extern const struct Hash SHA1;

extern const struct Hash SHA256;

extern const struct Hash SHA3_224;

extern const struct Hash SHA3_256;

extern const struct Hash SHA3_384;

extern const struct Hash SHA3_512;

extern const struct Hash SHA3_512_224;

extern const struct Hash SHA3_512_256;

extern const struct Hash SHA512;

extern const struct Symmetric AES128;

extern const struct Symmetric AES192;

extern const struct Symmetric AES256;

extern const struct Symmetric TDEA;

int lenstra_validate_hash(const struct Hash *hash, uint16_t expiry);

int lenstra_validate_symmetric(const struct Symmetric *symmetric, uint16_t expiry);

int nist_validate_hash(const struct Hash *hash);

int nist_validate_symmetric(const struct Symmetric *symmetric, uint16_t expiry);

#endif /* WARDSTONE_BINDINGS_H */
