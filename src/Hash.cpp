#include <stdint.h>
#include <string.h>
#include "hash.h"
#include "utility/rmd160.h"
#include "utility/sha256.h"
#include "utility/sha512.h"

/*
 *  Single line hash functions.
 */

int rmd160(byte message[], size_t len, byte hash[20]){

   dword         MDbuf[5];            /* contains (A, B, C, D(, E))   */
   dword         X[16];               /* current 16-word chunk        */
   dword         i;                   /* counter                      */
   dword         length;              /* length in bytes of message   */
   dword         nbytes;              /* # of bytes not yet processed */

   /* initialize */
   MDinit(MDbuf);
   // length = (dword)strlen((char *)message);
   length = len;

   /* process message in 16-word chunks */
   for (nbytes=length; nbytes > 63; nbytes-=64) {
      for (i=0; i<16; i++) {
         X[i] = BYTES_TO_DWORD(message);
         message += 4;
      }
      MDcompress(MDbuf, X);
   }                                    /* length mod 64 bytes left */

   /* finish: */
   MDfinish(MDbuf, message, length, 0);

   for (i=0; i<20; i+=4) {
      hash[i]   =  MDbuf[i>>2];         /* implicit cast to byte  */
      hash[i+1] = (MDbuf[i>>2] >>  8);  /*  extracts the 8 least  */
      hash[i+2] = (MDbuf[i>>2] >> 16);  /*  significant bits.     */
      hash[i+3] = (MDbuf[i>>2] >> 24);
   }

   return 20;
}

int sha256(byte message[], size_t len, byte hash[32]){

	struct SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, message, len);
	sha256_final(&ctx, hash);
	return 32;
}

int hash160(byte message[], size_t len, byte hash[32]){
	byte buffer[32] = { 0 };

	sha256(message, len, buffer);
	rmd160(buffer, sizeof(buffer), hash);
	memset(buffer, 0, 32);
	return 20;
}

int doubleSha(byte message[], size_t len, byte hash[32]){
	byte buffer[32] = { 0 };

	sha256(message, len, buffer);
	sha256(buffer, sizeof(buffer), hash);
	memset(buffer, 0, 32);
	return 32;
}

int sha512(byte message[], size_t len, byte hash[64]){
  SHA512 sha;
  sha.reset();
  sha.update(message, len);
  sha.finalize(hash, 64);
  return 64;
}

int sha512Hmac(byte key[], size_t keyLen, byte message[], size_t messageLen, byte hash[64]){
  SHA512 sha;
  sha.resetHMAC(key, keyLen);
  sha.update(message, messageLen);
  sha.finalizeHMAC(key, keyLen, hash, 64);
  return 64;
}

// following functions are required by uECC library to sign with deterministic k

void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_init(&context->ctx);
}

void update_SHA256(const uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size) {
    uint8_t msg[255] = {0};
    memcpy(msg, message, message_size);
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, msg, message_size);
}

void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash_result);
}
