#ifndef WARDSTONE_H
#define WARDSTONE_H
#include <stdint.h>

typedef struct Hash hash;
struct Hash {
  uint16_t digest_length;
};

typedef struct Symmetric symmetric;
struct Symmetric {
  uint16_t security;
};

extern const hash BLAKE2b_256;
extern const hash BLAKE2b_384;
extern const hash BLAKE2b_512;
extern const hash BLAKE2s_256;
extern const hash MD4;
extern const hash MD5;
extern const hash RIPEMD160;
extern const hash SHA1;
extern const hash SHA256;
extern const hash SHA3_224;
extern const hash SHA3_256;
extern const hash SHA3_384;
extern const hash SHA3_512;
extern const hash SHA3_512_224;
extern const hash SHA3_512_256;
extern const hash SHA512;

extern const symmetric AES128;
extern const symmetric AES196;
extern const symmetric AES256;
extern const symmetric TDEA;

extern int lenstra_validate_hash(const hash*, uint16_t);
extern int lenstra_validate_symmetric(const symmetric*, uint16_t);
extern int nist_validate_hash(const hash*);
extern int nist_validate_symmetric(const symmetric*, uint16_t);
#endif /* WARDSTONE_H */
