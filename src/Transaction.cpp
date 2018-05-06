#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include "Bitcoin.h"
#include "Hash.h"
#include "BaseX.h"
#include "utility/sha256.h"

// TRANSACTION CLASS
Transaction::Transaction(void){
    len = 0;
    inputsNumber = 0;
    outputsNumber = 0;
}
Transaction::~Transaction(void) {
    if(len > 0){
        len = 0;
        free(raw_data);
    }
}
int Transaction::parse(char raw[]){
    parse(raw, strlen(raw));
}
int Transaction::parse(char raw[], size_t l){
    if(len > 0){
        free(raw_data);
        len = 0;
    }
    if(l % 2 > 0){
        Serial.println(l);
        Serial.println("Should be 2 characters per byte");
        return 1; // should be 2 characters per byte
    }
    len = l/2;
    raw_data = ( uint8_t * ) calloc( len, sizeof(uint8_t) );
    for(size_t i=0; i<len; i++){
        raw_data[i] = (hexToVal(raw[2*i]) * 16) + hexToVal(raw[2*i+1]);
    }
    Serial.println(toHex(raw_data, len));
    // parsing
    size_t cursor = 0;
    cursor += 4; // version
    inputsNumber = raw_data[cursor] & 0xFF;
    Serial.println(raw_data[cursor]);
    cursor ++;
    for(int i=0; i<inputsNumber; i++){
        cursor += 32; // hash
        cursor += 4; // output index
        size_t script_len = raw_data[cursor];
        cursor ++;
        cursor += script_len; // script sig
        cursor += 4; // sequence
    }
    outputsNumber = raw_data[cursor] & 0xFF;
    Serial.println(raw_data[cursor]);
    cursor ++;
    for(int i=0; i<outputsNumber; i++){
        cursor += 8; // value
        size_t script_len = raw_data[cursor];
        cursor ++;
        cursor += script_len;
    }
    cursor += 4; // locktime
    if(cursor != len){
        free(raw_data);
        len = 0;
    }
    return len;
}

String Transaction::outputAddress(int outputNumber, bool testnet){
    size_t cursor = 0;
    cursor += 4; // version
    inputsNumber = raw_data[cursor] & 0xFF;
    cursor ++;
    for(int i=0; i<inputsNumber; i++){
        cursor += 32; // hash
        cursor += 4; // output index
        size_t script_len = raw_data[cursor];
        cursor ++;
        cursor += script_len; // script sig
        cursor += 4; // sequence
    }
    outputsNumber = raw_data[cursor] & 0xFF;
    cursor ++;
    for(int i=0; i<outputNumber; i++){
        cursor += 8; // value
        size_t script_len = raw_data[cursor];
        cursor ++;
        cursor += script_len;
    }
    cursor += 8; // value
    size_t script_len = raw_data[cursor];
    cursor ++;
    if(script_len == 25){
        uint8_t addr[21];
        if(testnet){
            addr[0] = BITCOIN_TESTNET_P2PKH;
        }else{
            addr[0] = BITCOIN_MAINNET_P2PKH;
        }
        memcpy(addr+1, raw_data + cursor + 3, 20);
        char address[40] = { 0 };
        toBase58Check(addr, 21, address, sizeof(address));
        return String(address);
    }else{
        return String("Unsupported: ")+toHex(raw_data+cursor, script_len);
    }
}

float Transaction::outputValue(int outputNumber){
    size_t cursor = 0;
    cursor += 4; // version
    inputsNumber = raw_data[cursor] & 0xFF;
    cursor ++;
    for(int i=0; i<inputsNumber; i++){
        cursor += 32; // hash
        cursor += 4; // output index
        size_t script_len = raw_data[cursor];
        cursor ++;
        cursor += script_len; // script sig
        cursor += 4; // sequence
    }
    outputsNumber = raw_data[cursor] & 0xFF;
    cursor ++;
    for(int i=0; i<outputNumber; i++){
        cursor += 8; // value
        size_t script_len = raw_data[cursor];
        cursor ++;
        cursor += script_len;
    }
    uint64_t v = 0;
    for(int i=7; i>=0; i--){
        v <<= 8;
        v += (raw_data[cursor+i] & 0xFF);
    }
    return v;
}

int Transaction::getHash(int index, PublicKey pubkey, uint8_t hash2[32]){
    size_t cursor = 0;
    uint8_t hash[32] = { 0 };
    struct SHA256_CTX ctx;

    sha256_init(&ctx);

    // Serial.print(toHex(raw_data+cursor, 4));
    sha256_update(&ctx, raw_data+cursor, 4);
    cursor += 4; // version
    inputsNumber = raw_data[cursor] & 0xFF;
    // Serial.print(toHex(raw_data+cursor, 1));
    sha256_update(&ctx, raw_data+cursor, 1);
    cursor ++;
    for(int i=0; i<inputsNumber; i++){
        // Serial.print(toHex(raw_data+cursor, 32));
        sha256_update(&ctx, raw_data+cursor, 32);
        cursor += 32; // hash
        // Serial.print(toHex(raw_data+cursor, 4));
        sha256_update(&ctx, raw_data+cursor, 4);
        cursor += 4; // output index
        if(index == i){
            // Serial.print("19");
            // Serial.print("76a914");
            uint8_t arr[4] = {0x19, 0x76, 0xa9, 0x14};
            sha256_update(&ctx, arr, 4);

            uint8_t buffer[32];
            uint8_t sec_arr[65] = { 0 };
            int l = pubkey.sec(sec_arr, sizeof(sec_arr));
            hash160(sec_arr, l, buffer);
            // Serial.print(toHex(buffer, 20));
            sha256_update(&ctx, buffer, 20);
            uint8_t arr2[2] = {0x88, 0xac};
            sha256_update(&ctx, arr2, 2);
            // Serial.print("88ac");
        }else{
            uint8_t arr[1] = { 0x00 };
            sha256_update(&ctx, arr, 1);
            // Serial.print("00");
        }
        size_t script_len = raw_data[cursor];
        cursor ++;
        cursor += script_len; // script sig
        // Serial.print(toHex(raw_data+cursor, 4));
        sha256_update(&ctx, raw_data+cursor, 4);
        cursor += 4; // sequence
    }
    // Serial.print(toHex(raw_data+cursor, len-cursor));
    sha256_update(&ctx, raw_data+cursor, len-cursor);
    // Serial.println("01000000");
    uint8_t sighash_all[4] = { 0x01, 0x00, 0x00, 0x00 };
    sha256_update(&ctx, sighash_all, 4);

    sha256_final(&ctx, hash);
    sha256(hash, 32, hash2);
    return 0;
}

String Transaction::sign(HDPrivateKey key){
    if(len == 0){
        return String("Invalid transaction");
    }
    size_t cursor = 0;
    String result = "";
    result += toHex(raw_data + cursor, 4);
    cursor += 4; // version
    inputsNumber = raw_data[cursor] & 0xFF;
    result += toHex(raw_data + cursor, 1);
    cursor ++;
    for(int i=0; i<inputsNumber; i++){
        result += toHex(raw_data + cursor, 32+4);
        cursor += 32; // hash
        cursor += 4; // output index
        size_t script_len = raw_data[cursor];
        cursor ++;
        if(script_len > 0){
            size_t offset = 0;
            offset += 5 + 78;
            HDPrivateKey myKey = key;
            for(int j=0; j<(script_len-offset)/2; j++){
                uint16_t der = 0;
                der += (raw_data[cursor+offset+2*j+1] & 0xFF);
                der *= 8;
                der += (raw_data[cursor+offset+2*j] & 0xFF);
                myKey = myKey.child(der);
            }
            PublicKey pubkey = myKey.privateKey.publicKey();
            // Serial.println(pubkey.getAddress());
            uint8_t hash[32] = { 0 };
            getHash(i, pubkey, hash);
            // Serial.println(toHex(hash, 32));
            Signature sig = myKey.privateKey.sign(hash);
            uint8_t der[80] = { 0 };
            size_t derLen = sig.der(der, sizeof(der));
            der[derLen] = 1;
            derLen++;
            uint8_t sec[65] = { 0 };
            size_t secLen = pubkey.sec(sec, sizeof(sec));
            uint8_t lenArr[2] = { secLen + derLen + 2, derLen };
            result += toHex(lenArr, 2);
            result += toHex(der, derLen);
            uint8_t lenArr2[1] = { secLen };
            result += toHex(lenArr2, 1);
            result += toHex(sec, secLen);
            // HDPrivateKey derivedKey
        }else{
            return String("Unable to sign");
        }
        cursor += script_len; // script sig
        result += toHex(raw_data + cursor, 4);
        cursor += 4; // sequence
    }
    result += toHex(raw_data + cursor, len-cursor);
    return result;
}