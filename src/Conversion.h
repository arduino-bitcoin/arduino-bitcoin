#ifndef BASEX_H_6LV8N942E3
#define BASEX_H_6LV8N942E3

#include <Arduino.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include "utility/segwit_addr.h"

// TODO: get rid of these blahLength functions, they are redundant
//       just stop when array is full and return errorcode
size_t toBase58Length(const uint8_t * array, size_t arraySize);
size_t toBase58(const uint8_t * array, size_t arraySize, char * output, size_t outputSize);
String toBase58(const uint8_t * array, size_t arraySize);

// base58 conversion with 4-byte checksum at the end (doubleSha)
size_t toBase58Check(const uint8_t * array, size_t arraySize, char * output, size_t outputSize);
String toBase58Check(const uint8_t * array, size_t arraySize);

size_t fromBase58Length(const char * array, size_t arraySize);
size_t fromBase58(const char * encoded, size_t encodedSize, uint8_t * output, size_t outputSize);
size_t fromBase58Check(const char * encoded, size_t encodedSize, uint8_t * output, size_t outputSize);
size_t fromBase58(String encoded, uint8_t * output, size_t outputSize);
size_t fromBase58Check(String encoded, uint8_t * output, size_t outputSize);

size_t toHex(const uint8_t * array, size_t arraySize, char * output, size_t outputSize);
String toHex(const uint8_t * array, size_t arraySize);
size_t toHex(uint8_t v, Print &s); // printing single hex value to Print
size_t toHex(const uint8_t * array, size_t arraySize, Print &s); // printing array in hex Print

size_t fromHex(const char * hex, uint8_t * array, size_t arraySize);
size_t fromHex(const char * hex, size_t hexLen, uint8_t * array, size_t arraySize);

uint8_t hexToVal(char c);

/* int conversion */
uint64_t littleEndianToInt(const uint8_t * array, size_t arraySize);
void intToLittleEndian(uint64_t num, uint8_t * array, size_t arraySize);
uint64_t bigEndianToInt(const uint8_t * array, size_t arraySize);
void intToBigEndian(uint64_t num, uint8_t * array, size_t arraySize);

/* varint */
uint8_t lenVarInt(uint64_t num); // returns length of the array required for varint encoding
uint64_t readVarInt(const uint8_t * array, size_t arraySize);
uint64_t readVarInt(Stream &s);
size_t writeVarInt(uint64_t num, uint8_t * array, size_t arraySize);
size_t writeVarInt(uint64_t num, Stream &s);

/* Stream converters */

/* ByteStream class
   Converts an array of bytes to stream of bytes.
   Useful for transaction parsing.
 */
class ByteStream : public Stream{
    size_t len = 0;
    size_t cursor = 0;
    uint8_t * buf = NULL;
public:
    ByteStream();
    ByteStream(uint8_t * buffer, size_t length);
    ~ByteStream();
    int available();
    int read();
    int peek();
    void flush();
    size_t readBytes( uint8_t * buffer, size_t length);
    size_t write(uint8_t b);
    size_t write(uint8_t * arr, size_t length);
};



#endif // BASEX_H_6LV8N942E3