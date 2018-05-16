/*
    TODO: 
    write description
    split to several headers files - will be easier to read
    This file defines the public interface. 
 */

#ifndef __BITCOIN_H__BDDNDVJ300
#define __BITCOIN_H__BDDNDVJ300

#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include "Conversion.h"

/*
    Constants.
*/
#define EMPTY_KEY 0
#define INVALID_KEY 1

#define PBKDF2_ROUNDS 2048 // number of rounds for mnemonic to seed conversion

#define BITCOIN_MAINNET_PREFIX 0x80
#define BITCOIN_TESTNET_PREFIX 0xEF
#define BITCOIN_MAINNET_P2PKH  0x00
#define BITCOIN_TESTNET_P2PKH  0x6F
#define BITCOIN_MAINNET_P2SH   0x05
#define BITCOIN_TESTNET_P2SH   0xC4

// TODO: think if we need P2PKH_COMPRESSED/UNCOMPRESSED
#define P2PKH                  1
#define P2SH                   2
#define P2WPKH                 3
#define P2WSH                  4
#define P2SHWPKH               5 // TODO: how is it normally called?

class PublicKey; // forward definition
/*
    Signature class.
*/
class Signature{
        uint8_t r[32];
        uint8_t s[32];
    public:
        Signature();
        Signature(byte r_arr[32], byte s_arr[32]);
        Signature(byte der[]); // parses binary array
        Signature(char der[]); // parses hex string
        size_t der(uint8_t * bytes, size_t len);
        void bin(byte arr[64]); // 64-byte array <r[32]><s[32]>
        operator String();
};

/* 
 *  Script class
 */

class Script{
public:
    // TODO: move to protected / private
    // TODO: length() function instead of variable
    uint8_t * script = NULL;
    size_t scriptLen = 0;

    Script();
    Script(uint8_t * buffer, size_t len);
    Script(PublicKey pubkey, int type = P2PKH); // creates one of standart scripts
    Script(Script const &other);
    ~Script();
    size_t parse(Stream &s);
    int type();
    String address(bool testnet = false);
    size_t length(); // length of the serialized bytes sequence
    size_t serialize(Stream &s); // serialize to Stream
    size_t serialize(uint8_t array[], size_t len); // serialize to array

    Script &operator=(Script const &other);
    operator String();
private:
    void clear();
};

/*
    PublicKey class.
    Compressed flag determines what public key sec format to use by default.
        compressed = false will use 65-byte representation (04<x><y>)
        compressed = true will use 33-byte representation (03<x> if y is odd, 02<x> if y is even)
    Testnet flag should be set if you want to use bitcoin testnet, not mainnet.
 */
class PublicKey{
    public:
        byte point[64];  // point on curve (x,y)
        bool compressed;
        bool testnet;

        PublicKey();
        PublicKey(byte pubkeyArr[64], bool use_compressed, bool use_testnet = false);
        PublicKey(byte secArr[], bool use_testnet = false);
        PublicKey(char secHex[], bool use_testnet = false); // fromHex method will be better
        int sec(byte sec[], size_t len);
        String sec();
        int fromSec(byte secArr[], bool use_testnet = false);
        int address(char * address, size_t len);
        String address();
        int segwitAddress(char * address, size_t len);
        String segwitAddress();
        int nestedSegwitAddress(char * address, size_t len);
        String nestedSegwitAddress();
        bool verify(Signature sig, byte hash[32]);
        bool isValid();
        Script script(int type = P2PKH);
        operator String();
};

/*
    PrivateKey class. 
    Corresponding public key (point on curve) will be calculated in the constructor.
        as point calculation is pretty slow, class initialization can take some time.
    TODO: move secret to private, make setSecret, getSecret
    TODO: make exportable flag in constructor or lock() function to disable export
*/
class PrivateKey{
        PublicKey pubKey;  // corresponding point on curve ( secret * G )
    public:
        uint8_t secret[32]; // 32-byte secret

        PrivateKey();
        PrivateKey(uint8_t secret_arr[], bool use_compressed = true, bool use_testnet = false);
        PrivateKey(const char wifArr[]);
        PrivateKey(const String wifString);
        ~PrivateKey();

        bool isValid();

        bool compressed;    // set to true if you want to use compressed public key format
        bool testnet;       // set to true for testnet

        int wif(char wifArr[], size_t len); // writes wallet import format string to wif array. 51 or 52 characters are required.
        String wif();
        int fromWIF(const char wifArr[], size_t wifSize);
        int fromWIF(const char wifArr[]);
        PublicKey publicKey();
        Signature sign(byte hash[32]); // pass 32-byte hash of the message here

        // Aliases for .publicKey().address() etc
        int address(char address[], size_t len);
        String address();
        int segwitAddress(char address[], size_t len);
        String segwitAddress();
        int nestedSegwitAddress(char address[], size_t len);
        String nestedSegwitAddress();

        // operators override
        bool operator==(const PrivateKey& other) const;
        bool operator==(const int& other) const;
        bool operator!=(const PrivateKey& other) const;
        bool operator!=(const int& other) const;
        PrivateKey& operator= (const char * s) { this->fromWIF(s); return *this; }
        operator String(){ return wif(); };

};

/*
    HD Private Key class.
    Classes are defined in HDWallet.cpp
*/
class HDPrivateKey{
    public:
        HDPrivateKey();
        HDPrivateKey(uint8_t secret[32], uint8_t chain_code[32], 
                     uint8_t key_depth = 0,
                     uint8_t fingerprint_arr[4] = NULL,
                     uint32_t childnumber = 0,
                     bool use_testnet = false);
        HDPrivateKey(char xprvArr[]);
        ~HDPrivateKey();

        PrivateKey privateKey;
        uint8_t chainCode[32];
        uint8_t depth;
        uint8_t fingerprint[4];
        uint32_t childNumber;

        int fromSeed(uint8_t seed[64], bool use_testnet = false);
        int fromMnemonic(char mnemonic[], char password[], bool use_testnet = false);
        int xprv(char arr[], size_t len);
        int xpub(char arr[], size_t len);
        String xprv();
        String xpub();

        HDPrivateKey child(uint32_t index);
        HDPrivateKey hardenedChild(uint32_t index);
        bool isValid();
        operator String(){ return xprv(); };
};

class HDPublicKey{
    public:
        HDPublicKey();
        HDPublicKey(uint8_t point[64], uint8_t chain_code[32], 
                     uint8_t key_depth = 0,
                     uint8_t fingerprint_arr[4] = NULL,
                     uint32_t childnumber = 0,
                     bool use_testnet = false);
        HDPublicKey(char xpubArr[]);
        ~HDPublicKey();

        PublicKey publicKey;
        uint8_t chainCode[32];
        uint8_t depth;
        uint8_t fingerprint[4];
        uint32_t childNumber;

        int xpub(char arr[], size_t len);
        String xpub();

        HDPublicKey child(uint32_t index);
        bool isValid();
        operator String(){ return xpub(); };
};

/*
 *  Transaction classes.
 *  Classes are defined in Transaction.cpp file.
 *  TODO: handle large transactions and invalid inputs somehow...
 */

class TransactionInput{
public:
    TransactionInput();
    TransactionInput(byte prev_hash[32], uint32_t prev_index);
    TransactionInput(byte prev_hash[32], uint32_t prev_index, Script script, uint32_t sequence_number = 0xffffffff);
    TransactionInput(byte prev_hash[32], uint32_t prev_index, uint32_t sequence_number, Script script);
    TransactionInput(Stream & s){ parse(s); };
    TransactionInput(byte raw[], size_t len){ parse(raw, len); };

    uint8_t hash[32];
    uint32_t outputIndex;
    Script scriptSig;
    uint32_t sequence;

    // following information is optional, 
    // can be obtained from spending output
    Script scriptPubKey;
    uint64_t amount = 0; // required for fee calculation

    size_t parse(Stream &s);
    size_t parse(byte raw[], size_t len);
    size_t length(); // length of the serialized bytes sequence
    size_t length(Script script_pubkey); // length of the serialized bytes sequence with custom script
    size_t serialize(Stream &s); // serialize to Stream
    size_t serialize(Stream &s, Script script_pubkey); // serialize to stream with custom script
    size_t serialize(uint8_t array[], size_t len); // serialize to array
    size_t serialize(uint8_t array[], size_t len, Script script_pubkey); // use custom script for serialization
};

class TransactionOutput{
public:
    TransactionOutput();
    TransactionOutput(uint64_t send_amount, Script outputScript);
    TransactionOutput(Stream & s){ parse(s); };
    TransactionOutput(byte raw[], size_t len){ parse(raw, len); };

    uint64_t amount = 0;
    Script scriptPubKey;

    size_t parse(Stream &s);
    size_t parse(byte raw[], size_t l);
    String address(bool testnet=false);

    size_t length(); // length of the serialized bytes sequence
    size_t serialize(Stream &s); // serialize to Stream
    size_t serialize(uint8_t array[], size_t len); // serialize to array
};

class Transaction{
public:
    Transaction();
    Transaction(Stream &s){ parse(s); };
    Transaction(byte raw[], size_t len){ parse(raw, len); };
    ~Transaction();

    uint32_t version = 1;
    TransactionInput * txIns = NULL;
    TransactionOutput * txOuts = NULL;
    uint32_t locktime = 0;

    size_t parse(Stream &s);
    size_t parse(byte raw[], size_t len);
    size_t inputsNumber;
    size_t outputsNumber;
    uint8_t addInput(TransactionInput txIn);
    uint8_t addOutput(TransactionOutput txOut);

    size_t length(); // length of the serialized bytes sequence
    size_t serialize(Stream &s); // serialize to Stream
    size_t serialize(uint8_t array[], size_t len); // serialize to array

    // populates hash with transaction hash
    int hash(uint8_t hash[32]);
    // populates hash with data for signing certain input with particular scriptPubkey
    int sigHash(uint8_t inputNumber, Script scriptPubKey, uint8_t hash[32]);
    // TODO:
    // String sign(HDPrivateKey key);
    // TODO: copy()
    // TODO: sort() - bip69, Lexicographical Indexing of Transaction Inputs and Outputs
};

#endif /* __BITCOIN_H__BDDNDVJ300 */