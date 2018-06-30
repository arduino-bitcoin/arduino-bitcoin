#include "sha256.h"
#include "sha512.h"
#include "RotateUtil.h"
#include "EndianUtil.h"
#include "ProgMemUtil.h"
#include <string.h>

//Derived from https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c written by Brad Conte
//Ported to Arduino by Steven Pearson
//This code is released into the public domain free of any restrictions.
//The authors request acknowledgement if the code is used, but does not require it.
//This code is provided free of any liability and without any quality claims by the authors.


// const uint32_t k[] PROGMEM = {
const uint32_t k[] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// const uint32_t SHA256INITIALSTATE[] PROGMEM = {
const uint32_t SHA256INITIALSTATE[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};


inline uint32_t ROTR(uint32_t number,uint32_t bits){
  return ((number << (32-bits)) | (number >> bits));
}

inline uint32_t SHR(uint32_t number,uint32_t bits){
  return number >> bits;
}

inline uint32_t Sigma0(uint32_t x){
  return ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3);
}

inline uint32_t Sigma1(uint32_t x){
  return ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10);
}

inline uint32_t Epsilon0(uint32_t x){
  return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22);
}

inline uint32_t Epsilon1(uint32_t x){
  return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25);
}

inline uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){
  return (x&y)^(~x&z);
}

inline uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){
  return (x&y)^(x&z)^(y&z);
}

inline void sha256_transform(struct SHA256_CTX *ctx, uint8_t data[])
{
   uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
      
   for (i=0,j=0; i < 16; ++i, j += 4){
      m[i] = ((uint32_t)data[j] << 24ul) | ((uint32_t)data[j+1] << 16ul) | ((uint32_t)data[j+2] << 8ul) | ((uint32_t)data[j+3]);
   }
   for ( ; i < 64; ++i){
      m[i] = Sigma1(m[i-2]) + m[i-7] + Sigma0(m[i-15]) + m[i-16];
   }
     
   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];
   f = ctx->state[5];
   g = ctx->state[6];
   h = ctx->state[7];

   for (i = 0; i < 64; ++i) {
      t1 = h + Epsilon1(e) + Ch(e,f,g) + k[i] + m[i];
      t2 = Epsilon0(a) + Maj(a,b,c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
   }   
   
   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
   ctx->state[5] += f;
   ctx->state[6] += g;
   ctx->state[7] += h;
}

void sha256_init(struct SHA256_CTX *ctx)
{ 
   ctx->datalen = 0; 
   ctx->bitlen = 0;
   memcpy(ctx->state,SHA256INITIALSTATE,8*sizeof(uint32_t));
}

void sha256_update(struct SHA256_CTX *ctx, uint8_t data[], size_t len)
{ 
   uint32_t t,i;
   
   for (i=0; i < len; ++i) { 
      ctx->data[ctx->datalen] = data[i]; 
      ctx->datalen++; 
      if (ctx->datalen == 64) { 
         sha256_transform(ctx,ctx->data);
         ctx->bitlen += 512;
         ctx->datalen = 0;
      }  
   }  
}

void sha256_final(struct SHA256_CTX *ctx, uint8_t hash[])
{
   uint32_t i; 
   
   i = ctx->datalen; 
   
   // Pad whatever data is left in the buffer. 
   if (ctx->datalen < 56) {
      ctx->data[i++] = 0x80; 
      while (i < 56) 
         ctx->data[i++] = 0x00; 
   }  
   else { 
      ctx->data[i++] = 0x80; 
      while (i < 64) 
         ctx->data[i++] = 0x00; 
      sha256_transform(ctx,ctx->data);
      memset(ctx->data,0,56); 
   }  
   
   // Append to the padding the total message's length in bits and transform. 
   ctx->bitlen += ctx->datalen * 8;
   ctx->data[63] = ctx->bitlen;
   ctx->data[62] = ctx->bitlen >> 8; 
   ctx->data[61] = ctx->bitlen >> 16;  
   ctx->data[60] = ctx->bitlen >> 24; 
   ctx->data[59] = ctx->bitlen >> 32;
   ctx->data[58] = ctx->bitlen >> 40; 
   ctx->data[57] = ctx->bitlen >> 48; 
   ctx->data[56] = ctx->bitlen >> 56; 
   sha256_transform(ctx,ctx->data);
   
   // Since this implementation uses little endian byte ordering and SHA uses big endian,
   // reverse all the bytes when copying the final state to the output hash. 
   for (i=0; i < 4; ++i) { 
      hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff; 
      hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff; 
      hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
      hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
      hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
      hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0x000000ff;
      hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0x000000ff;
      hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0x000000ff;
   }
}

SHA256::SHA256()
{
    reset();
}

/**
 * \brief Destroys this SHA-256 hash object after clearing
 * sensitive information.
 */
SHA256::~SHA256()
{
    clean(state);
}

size_t SHA256::hashSize() const
{
    return 32;
}

size_t SHA256::blockSize() const
{
    return 64;
}

void SHA256::reset()
{
    state.h[0] = 0x6a09e667;
    state.h[1] = 0xbb67ae85;
    state.h[2] = 0x3c6ef372;
    state.h[3] = 0xa54ff53a,
    state.h[4] = 0x510e527f;
    state.h[5] = 0x9b05688c;
    state.h[6] = 0x1f83d9ab;
    state.h[7] = 0x5be0cd19;
    state.chunkSize = 0;
    state.length = 0;
}

void SHA256::update(const void *data, size_t len)
{
    // Update the total length (in bits, not bytes).
    state.length += ((uint64_t)len) << 3;

    // Break the input up into 512-bit chunks and process each in turn.
    const uint8_t *d = (const uint8_t *)data;
    while (len > 0) {
        uint8_t size = 64 - state.chunkSize;
        if (size > len)
            size = len;
        memcpy(((uint8_t *)state.w) + state.chunkSize, d, size);
        state.chunkSize += size;
        len -= size;
        d += size;
        if (state.chunkSize == 64) {
            processChunk();
            state.chunkSize = 0;
        }
    }
}

void SHA256::finalize(void *hash, size_t len)
{
    // Pad the last chunk.  We may need two padding chunks if there
    // isn't enough room in the first for the padding and length.
    uint8_t *wbytes = (uint8_t *)state.w;
    if (state.chunkSize <= (64 - 9)) {
        wbytes[state.chunkSize] = 0x80;
        memset(wbytes + state.chunkSize + 1, 0x00, 64 - 8 - (state.chunkSize + 1));
        state.w[14] = htobe32((uint32_t)(state.length >> 32));
        state.w[15] = htobe32((uint32_t)state.length);
        processChunk();
    } else {
        wbytes[state.chunkSize] = 0x80;
        memset(wbytes + state.chunkSize + 1, 0x00, 64 - (state.chunkSize + 1));
        processChunk();
        memset(wbytes, 0x00, 64 - 8);
        state.w[14] = htobe32((uint32_t)(state.length >> 32));
        state.w[15] = htobe32((uint32_t)state.length);
        processChunk();
    }

    // Convert the result into big endian and return it.
    for (uint8_t posn = 0; posn < 8; ++posn)
        state.w[posn] = htobe32(state.h[posn]);

    // Copy the hash to the caller's return buffer.
    if (len > 32)
        len = 32;
    memcpy(hash, state.w, len);
}

void SHA256::clear()
{
    clean(state);
    reset();
}

void SHA256::resetHMAC(const void *key, size_t keyLen)
{
    formatHMACKey(state.w, key, keyLen, 0x36);
    state.length += 64 * 8;
    processChunk();
}

void SHA256::finalizeHMAC(const void *key, size_t keyLen, void *hash, size_t hashLen)
{
    uint8_t temp[32];
    finalize(temp, sizeof(temp));
    formatHMACKey(state.w, key, keyLen, 0x5C);
    state.length += 64 * 8;
    processChunk();
    update(temp, sizeof(temp));
    finalize(hash, hashLen);
    clean(temp);
}

/**
 * \brief Processes a single 512-bit chunk with the core SHA-256 algorithm.
 *
 * Reference: http://en.wikipedia.org/wiki/SHA-2
 */
void SHA256::processChunk()
{
    // Round constants for SHA-256.
    static uint32_t const k[64] PROGMEM = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Convert the first 16 words from big endian to host byte order.
    uint8_t index;
    for (index = 0; index < 16; ++index)
        state.w[index] = be32toh(state.w[index]);

    // Initialise working variables to the current hash value.
    uint32_t a = state.h[0];
    uint32_t b = state.h[1];
    uint32_t c = state.h[2];
    uint32_t d = state.h[3];
    uint32_t e = state.h[4];
    uint32_t f = state.h[5];
    uint32_t g = state.h[6];
    uint32_t h = state.h[7];

    // Perform the first 16 rounds of the compression function main loop.
    uint32_t temp1, temp2;
    for (index = 0; index < 16; ++index) {
        temp1 = h + pgm_read_dword(k + index) + state.w[index] +
                (rightRotate6(e) ^ rightRotate11(e) ^ rightRotate25(e)) +
                ((e & f) ^ ((~e) & g));
        temp2 = (rightRotate2(a) ^ rightRotate13(a) ^ rightRotate22(a)) +
                ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Perform the 48 remaining rounds.  We expand the first 16 words to
    // 64 in-place in the "w" array.  This saves 192 bytes of memory
    // that would have otherwise need to be allocated to the "w" array.
    for (; index < 64; ++index) {
        // Expand the next word.
        temp1 = state.w[(index - 15) & 0x0F];
        temp2 = state.w[(index - 2) & 0x0F];
        temp1 = state.w[index & 0x0F] =
            state.w[(index - 16) & 0x0F] + state.w[(index - 7) & 0x0F] +
                (rightRotate7(temp1) ^ rightRotate18(temp1) ^ (temp1 >> 3)) +
                (rightRotate17(temp2) ^ rightRotate19(temp2) ^ (temp2 >> 10));

        // Perform the round.
        temp1 = h + pgm_read_dword(k + index) + temp1 +
                (rightRotate6(e) ^ rightRotate11(e) ^ rightRotate25(e)) +
                ((e & f) ^ ((~e) & g));
        temp2 = (rightRotate2(a) ^ rightRotate13(a) ^ rightRotate22(a)) +
                ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Add the compressed chunk to the current hash value.
    state.h[0] += a;
    state.h[1] += b;
    state.h[2] += c;
    state.h[3] += d;
    state.h[4] += e;
    state.h[5] += f;
    state.h[6] += g;
    state.h[7] += h;

    // Attempt to clean up the stack.
    a = b = c = d = e = f = g = h = temp1 = temp2 = 0;
}

void SHA256::formatHMACKey(void *block, const void *key, size_t len, uint8_t pad)
{
    size_t size = blockSize();
    reset();
    if (len <= size) {
        memcpy(block, key, len);
    } else {
        update(key, len);
        len = hashSize();
        finalize(block, len);
        reset();
    }
    uint8_t *b = (uint8_t *)block;
    memset(b + len, pad, size - len);
    while (len > 0) {
        *b++ ^= pad;
        --len;
    }
}

