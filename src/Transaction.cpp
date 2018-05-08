#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include "Bitcoin.h"
#include "Hash.h"
#include "Conversion.h"
#include "utility/sha256.h"

TransactionInput::TransactionInput(void){}
TransactionInput::TransactionInput(TransactionInput const &other){
    memcpy(hash, other.hash, 32);
    outputIndex = other.outputIndex;
    sequence = other.sequence;
    scriptLen = other.scriptLen;
    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    memcpy(script, other.script, scriptLen);
}
TransactionInput::~TransactionInput(void){
    if(scriptLen > 0){
        free(script);
    }
}
TransactionInput &TransactionInput::operator=(TransactionInput const &other){ 
    free(script);
    memcpy(hash, other.hash, 32);
    outputIndex = other.outputIndex;
    sequence = other.sequence;
    scriptLen = other.scriptLen;
    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    memcpy(script, other.script, scriptLen);
    return *this; 
};
size_t TransactionInput::parse(byte raw[], size_t len){
    size_t cursor = 0;
    memcpy(hash, raw, 32);
    cursor += 32; // hash

    outputIndex = littleEndianToInt(raw+cursor, 4);    
    cursor += 4; // output index

    if(scriptLen > 0){
        free(script);
    }
    // TODO: varint!!!
    scriptLen = raw[cursor];
    cursor ++;
    if(cursor+scriptLen > len){
        return 0;
    }

    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    memcpy(script, raw+cursor, scriptLen);
    cursor += scriptLen;

    sequence = littleEndianToInt(raw+cursor, 4);
    cursor += 4;

    return cursor;
}

TransactionOutput::TransactionOutput(void){}
TransactionOutput::TransactionOutput(TransactionOutput const &other){
    amount = other.amount;
    scriptLen = other.scriptLen;
    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    memcpy(script, other.script, scriptLen);
}
TransactionOutput::~TransactionOutput(void){}

size_t TransactionOutput::parse(byte raw[], size_t len){
    size_t cursor = 0;

    amount = littleEndianToInt(raw+cursor, 8);
    cursor += 8; // amount

    // TODO: varint!!!
    if(scriptLen > 0){
        free(script);
    }
    scriptLen = raw[cursor];
    cursor ++;
    if(cursor+scriptLen > len){
        return 0;
    }

    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    memcpy(script, raw+cursor, scriptLen);
    cursor += scriptLen;

    return cursor;
}
String TransactionOutput::address(bool testnet){
    if(scriptLen == 25){
        uint8_t addr[21];
        if(testnet){
            addr[0] = BITCOIN_TESTNET_P2PKH;
        }else{
            addr[0] = BITCOIN_MAINNET_P2PKH;
        }
        memcpy(addr+1, script + 3, 20);
        char address[40] = { 0 };
        toBase58Check(addr, 21, address, sizeof(address));
        return String(address);
    }else{
        return String("Unsupported: ")+toHex(script, scriptLen);
    }
}

TransactionOutput &TransactionOutput::operator=(TransactionOutput const &other){ 
    free(script);
    amount = other.amount;
    scriptLen = other.scriptLen;
    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    memcpy(script, other.script, scriptLen);
    return *this; 
};

// TODO: copy constructor, = operator
Transaction::Transaction(void){
    len = 0;
    inputsNumber = 0;
    outputsNumber = 0;
}
Transaction::~Transaction(void) {
    if(inputsNumber > 0){
        free(txIns);
    }
    if(outputsNumber > 0){
        free(txOuts);
    }
}
size_t Transaction::parse(byte raw[]){
    // parse(raw, strlen(raw));
}
size_t Transaction::parse(byte raw[], size_t l){
    if(inputsNumber > 0){
        free(txIns);
    }
    if(outputsNumber > 0){
        free(txOuts);
    }
    len = l;

    // parsing
    size_t cursor = 0;
    version = littleEndianToInt(raw, 4);
    cursor += 4;

    // varint, but currently supporting only up to 253 inputs
    inputsNumber = raw[cursor] & 0xFF;
    if(inputsNumber >= 0xFD){
        return 0;
    }
    if(txIns != NULL){
        free(txIns);
    }
    txIns = ( TransactionInput * )calloc( inputsNumber, sizeof(TransactionInput) );
    cursor ++;

    for(int i=0; i<inputsNumber; i++){
        TransactionInput txIn;
        cursor += txIn.parse(raw+cursor, len-cursor);
        txIns[i] = txIn;
        if(cursor > len){
            return 0;
        }
    }

    outputsNumber = raw[cursor] & 0xFF;
    if(outputsNumber >= 0xFD){
        return 0;
    }
    if(txOuts != NULL){
        free(txOuts);
    }
    txOuts = ( TransactionOutput * )calloc( outputsNumber, sizeof(TransactionOutput) );
    cursor ++;

    for(int i=0; i<outputsNumber; i++){
        TransactionOutput txOut;
        cursor += txOut.parse(raw+cursor, len-cursor);
        txOuts[i] = txOut;
        if(cursor > len){
            return 0;
        }
    }

    locktime = littleEndianToInt(raw+cursor, 4);
    cursor += 4;
    return cursor;
}

// String Transaction::outputAddress(int outputNumber, bool testnet){

// }

// float Transaction::outputValue(int outputNumber){

// }

// int Transaction::getHash(int index, PublicKey pubkey, uint8_t hash2[32]){
    // size_t cursor = 0;
    // uint8_t hash[32] = { 0 };
    // struct SHA256_CTX ctx;

    // sha256_init(&ctx);

    // sha256_update(&ctx, raw_data+cursor, 4);
    // cursor += 4; // version
    // inputsNumber = raw_data[cursor] & 0xFF;
    // sha256_update(&ctx, raw_data+cursor, 1);
    // cursor ++;
    // for(int i=0; i<inputsNumber; i++){
    //     sha256_update(&ctx, raw_data+cursor, 32);
    //     cursor += 32; // hash
    //     sha256_update(&ctx, raw_data+cursor, 4);
    //     cursor += 4; // output index
    //     if(index == i){
    //         uint8_t arr[4] = {0x19, 0x76, 0xa9, 0x14};
    //         sha256_update(&ctx, arr, 4);

    //         uint8_t buffer[32];
    //         uint8_t sec_arr[65] = { 0 };
    //         int l = pubkey.sec(sec_arr, sizeof(sec_arr));
    //         hash160(sec_arr, l, buffer);
    //         sha256_update(&ctx, buffer, 20);
    //         uint8_t arr2[2] = {0x88, 0xac};
    //         sha256_update(&ctx, arr2, 2);
    //     }else{
    //         uint8_t arr[1] = { 0x00 };
    //         sha256_update(&ctx, arr, 1);
    //     }
    //     size_t script_len = raw_data[cursor];
    //     cursor ++;
    //     cursor += script_len; // script sig
    //     sha256_update(&ctx, raw_data+cursor, 4);
    //     cursor += 4; // sequence
    // }
    // sha256_update(&ctx, raw_data+cursor, len-cursor);
    // uint8_t sighash_all[4] = { 0x01, 0x00, 0x00, 0x00 };
    // sha256_update(&ctx, sighash_all, 4);

    // sha256_final(&ctx, hash);
    // sha256(hash, 32, hash2);
    // return 0;
// }

// String Transaction::sign(HDPrivateKey key){
    // if(len == 0){
    //     return String("Invalid transaction");
    // }
    // size_t cursor = 0;
    // String result = "";
    // result += toHex(raw_data + cursor, 4);
    // cursor += 4; // version
    // inputsNumber = raw_data[cursor] & 0xFF;
    // result += toHex(raw_data + cursor, 1);
    // cursor ++;
    // for(int i=0; i<inputsNumber; i++){
    //     result += toHex(raw_data + cursor, 32+4);
    //     cursor += 32; // hash
    //     cursor += 4; // output index
    //     size_t script_len = raw_data[cursor];
    //     cursor ++;
    //     if(script_len > 0){
    //         size_t offset = 0;
    //         offset += 5 + 78;
    //         HDPrivateKey myKey = key;
    //         for(int j=0; j<(script_len-offset)/2; j++){
    //             uint16_t der = 0;
    //             der += (raw_data[cursor+offset+2*j+1] & 0xFF);
    //             der *= 8;
    //             der += (raw_data[cursor+offset+2*j] & 0xFF);
    //             myKey = myKey.child(der);
    //         }
    //         PublicKey pubkey = myKey.privateKey.publicKey();
    //         uint8_t hash[32] = { 0 };
    //         getHash(i, pubkey, hash);
    //         Signature sig = myKey.privateKey.sign(hash);
    //         uint8_t der[80] = { 0 };
    //         size_t derLen = sig.der(der, sizeof(der));
    //         der[derLen] = 1;
    //         derLen++;
    //         uint8_t sec[65] = { 0 };
    //         size_t secLen = pubkey.sec(sec, sizeof(sec));
    //         uint8_t lenArr[2] = { secLen + derLen + 2, derLen };
    //         result += toHex(lenArr, 2);
    //         result += toHex(der, derLen);
    //         uint8_t lenArr2[1] = { secLen };
    //         result += toHex(lenArr2, 1);
    //         result += toHex(sec, secLen);
    //         // HDPrivateKey derivedKey
    //     }else{
    //         return String("Unable to sign");
    //     }
    //     cursor += script_len; // script sig
    //     result += toHex(raw_data + cursor, 4);
    //     cursor += 4; // sequence
    // }
    // result += toHex(raw_data + cursor, len-cursor);
    // return result;
// }