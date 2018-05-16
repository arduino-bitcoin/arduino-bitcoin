#ifndef BASEX_H_6LV8N942E3
#define BASEX_H_6LV8N942E3

#include <Arduino.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>

// TODO: get rid of these blahLength functions, they are redundant
//       just stop when array is full and return errorcode
size_t toBase58Length(const uint8_t * array, size_t arraySize);
size_t toBase58(const uint8_t * array, size_t arraySize, char * output, size_t outputSize);

// base58 conversion with 4-byte checksum at the end (doubleSha)
size_t toBase58Check(const uint8_t * array, size_t arraySize, char * output, size_t outputSize);

size_t fromBase58Length(const char * array, size_t arraySize);
size_t fromBase58(const char * encoded, size_t encodedSize, uint8_t * output, size_t outputSize);
size_t fromBase58Check(const char * encoded, size_t encodedSize, uint8_t * output, size_t outputSize);

size_t toHex(const uint8_t * array, size_t arraySize, char * output, size_t outputSize);
String toHex(const uint8_t * array, size_t arraySize);

size_t fromHex(const char hex[], byte array[], size_t arraySize);
size_t fromHex(const char hex[], size_t hexLen, byte array[], size_t arraySize);

// TODO: implement the following functions:
// toBech32
// fromBech32

uint8_t hexToVal(char c);

/* int conversion */
uint64_t littleEndianToInt(byte array[], size_t arraySize);
void intToLittleEndian(uint64_t num, byte array[], size_t arraySize);
uint64_t bigEndianToInt(byte array[], size_t arraySize);
void intToBigEndian(uint64_t num, byte array[], size_t arraySize);

/* varint */
uint8_t lenVarInt(uint64_t num); // returns length of the array required for varint encoding
uint64_t readVarInt(byte array[], size_t arraySize);
uint64_t readVarInt(Stream &s);
size_t writeVarInt(uint64_t num, byte array[], size_t arraySize);
size_t writeVarInt(uint64_t num, Stream &s);

/* Stream convertors */

/* ByteStream class
   Converts an array of bytes to stream of bytes.
   Useful for transaction parsing.
 */
class ByteStream : public Stream{
	size_t len = 0;
	size_t cursor = 0;
	uint8_t * buf = NULL;
public:
	ByteStream(uint8_t * buffer, size_t length);
	~ByteStream();
	int available();
	int read();
	int peek();
	void flush();
	size_t readBytes( uint8_t * buffer, size_t length);
	size_t write(uint8_t);
};



#endif // BASEX_H_6LV8N942E3