#ifndef SHA256_H_IBUDV1051U
#define SHA256_H_IBUDV1051U
//Derived from https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c written by Brad Conte
//Ported to Arduino by Steven Pearson
//This code is released into the public domain free of any restrictions.
//The authors request acknowledgement if the code is used, but does not require it.
//This code is provided free of any liability and without any quality claims by the authors.

// #include <Arduino.h>
#include <stdint.h>
#include <string.h>

struct SHA256_CTX {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
};

void sha256_init(struct SHA256_CTX *ctx);
void sha256_update(struct SHA256_CTX *ctx, uint8_t data[], size_t len);
void sha256_final(struct SHA256_CTX *ctx, uint8_t hash[]);


/*
 * Copyright (C) 2015 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */


class SHA256{
public:
    SHA256();
    virtual ~SHA256();

    size_t hashSize() const;
    size_t blockSize() const;

    void reset();
    void update(const void *data, size_t len);
    void finalize(void *hash, size_t len);

    void clear();

    void resetHMAC(const void *key, size_t keyLen);
    void finalizeHMAC(const void *key, size_t keyLen, void *hash, size_t hashLen);

private:
    struct {
        uint32_t h[8];
        uint32_t w[16];
        uint64_t length;
        uint8_t chunkSize;
    } state;

    void processChunk();

protected:
    void formatHMACKey(void *block, const void *key, size_t len, uint8_t pad);
};

#endif // SHA256_H_IBUDV1051U