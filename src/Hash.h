#ifndef  HASH_H_18NLNNCSJ2           /* make sure this file is read only once */
#define  HASH_H_18NLNNCSJ2

#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include "utility/micro-ecc/uECC.h"
#include "utility/sha256.h"
#include "utility/sha512.h"

typedef    uint8_t         byte;


/*
 *  Single line hash functions.
 */

// RIPEMD-160
int rmd160(byte message[], size_t len, byte hash[20]);

// SHA-256
int sha256(byte message[], size_t len, byte hash[32]);

// RIPEMD-160( SHA-256( m ) )
int hash160(byte message[], size_t len, byte hash[20]);

// SHA-256( SHA-256( m ) )
int doubleSha(byte message[], size_t len, byte hash[32]);

// SHA-512
int sha512(byte message[], size_t len, byte hash[64]);
int sha512Hmac(byte key[], size_t keyLen, byte message[], size_t messageLen, byte hash[64]);

// TODO: stream version of hash functions

/*
 * Following functions are required by uECC library to sign with deterministic k
 */

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

void init_SHA256(const uECC_HashContext *base);
void update_SHA256(const uECC_HashContext *base, const uint8_t *message, unsigned message_size);
void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result);

#endif  /* HASH_H_18NLNNCSJ2 */
