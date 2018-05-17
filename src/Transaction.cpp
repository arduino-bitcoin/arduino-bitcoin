#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include "Bitcoin.h"
#include "Hash.h"
#include "Conversion.h"
#include "utility/sha256.h"

TransactionInput::TransactionInput(void){
    Script empty;
    scriptSig = empty;
}
// TODO: don't repeat yourself
TransactionInput::TransactionInput(byte prev_id[32], uint32_t prev_index, Script script, uint32_t sequence_number){
    // memcpy(hash, prev_id, 32);
    for(int i=0; i<32; i++){
        hash[i] = prev_id[31-i];
    }
    outputIndex = prev_index;
    scriptSig = script;
    sequence = sequence_number;
}
TransactionInput::TransactionInput(byte prev_id[32], uint32_t prev_index, uint32_t sequence_number, Script script){
    // TransactionInput(prev_id, prev_index, script, sequence_number);
    for(int i=0; i<32; i++){
        hash[i] = prev_id[31-i];
    }
    outputIndex = prev_index;
    scriptSig = script;
    sequence = sequence_number;
}
TransactionInput::TransactionInput(byte prev_id[32], uint32_t prev_index){
    Script script;
    uint32_t sequence_number = 0xffffffff;
    for(int i=0; i<32; i++){
        hash[i] = prev_id[31-i];
    }
    outputIndex = prev_index;
    scriptSig = script;
    sequence = sequence_number;
    // TransactionInput(prev_id, prev_index, script, sequence_number);
}
size_t TransactionInput::parse(Stream &s){
    size_t len = 0;
    len += s.readBytes(hash, 32);
    uint8_t arr[4];
    len += s.readBytes(arr, 4);
    outputIndex = littleEndianToInt(arr, 4);
    len += scriptSig.parse(s);
    len += s.readBytes(arr, 4);
    sequence = littleEndianToInt(arr, 4);
    if((len != 32+4+scriptSig.length()+4) || (scriptSig.length() == 0)){
        return 0;
    }
    return len;
}
size_t TransactionInput::parse(byte raw[], size_t len){
    ByteStream s(raw, len);
    return parse(s);
}
size_t TransactionInput::length(Script script){
    return 32 + 4 + script.length() + 4;
}
size_t TransactionInput::length(){
    return length(scriptSig);
}
size_t TransactionInput::serialize(Stream &s, Script script){
    size_t len = 0;
    s.write(hash, 32);
    len += 32;
    uint8_t arr[4];
    intToLittleEndian(outputIndex, arr, 4);
    s.write(arr, 4);
    len += 4;
    len += script.serialize(s);
    intToLittleEndian(sequence, arr, 4);
    s.write(arr, 4);
    len += 4;
    return len;
}
size_t TransactionInput::serialize(Stream &s){
    return serialize(s, scriptSig);
}
size_t TransactionInput::serialize(uint8_t array[], size_t len, Script script){
    // TODO: refactor with ByteStream
    if(len < length(script)){
        return 0;
    }
    size_t l = 0;
    memcpy(array, hash, 32);
    l += 32;
    intToLittleEndian(outputIndex, array+l, 4);
    l += 4;
    l += script.serialize(array+l, len-l);
    intToLittleEndian(sequence, array+l, 4);
    l += 4;
    return l;
}
size_t TransactionInput::serialize(uint8_t array[], size_t len){
    return serialize(array, len, scriptSig);
}
TransactionInput::TransactionInput(TransactionInput const &other){
    memcpy(hash, other.hash, 32);
    outputIndex = other.outputIndex;
    scriptSig = other.scriptSig;
    sequence = other.sequence;
}
TransactionInput &TransactionInput::operator=(TransactionInput const &other){ 
    memcpy(hash, other.hash, 32);
    outputIndex = other.outputIndex;
    scriptSig = other.scriptSig;
    sequence = other.sequence;
    return *this; 
};


TransactionOutput::TransactionOutput(void){
    amount = 0;
    Script empty;
    scriptPubKey = empty;
}
TransactionOutput::TransactionOutput(uint64_t send_amount, Script outputScript){
    amount = send_amount;
    scriptPubKey = outputScript;
}
TransactionOutput::TransactionOutput(uint64_t send_amount, char address[]){
    amount = send_amount;
    Script sc(address);
    scriptPubKey = sc;
}
size_t TransactionOutput::parse(Stream &s){
    size_t len = 0;
    uint8_t arr[8];
    len += s.readBytes(arr, 8);
    amount = littleEndianToInt(arr, 8);
    len += scriptPubKey.parse(s);
    if((len != 8+scriptPubKey.length()) || (scriptPubKey.length() == 0)){
        return 0;
    }
    return len;
}
size_t TransactionOutput::parse(byte raw[], size_t len){
    ByteStream s(raw, len);
    return parse(s);
}
String TransactionOutput::address(bool testnet){
    return scriptPubKey.address(testnet);
}
size_t TransactionOutput::length(){
    return 8+scriptPubKey.length();
}
size_t TransactionOutput::serialize(Stream &s){
    uint8_t arr[8];
    size_t len = 0;
    intToLittleEndian(amount, arr, 8);
    len += 8;
    s.write(arr, 8);
    len += scriptPubKey.serialize(s);
    return len;
}
size_t TransactionOutput::serialize(uint8_t array[], size_t len){
    if(len < length()){
        return 0;
    }
    intToLittleEndian(amount, array, 8);
    size_t l = 8;
    l += scriptPubKey.serialize(array+l, len-l);
    return l;
}
TransactionOutput::TransactionOutput(TransactionOutput const &other){
    amount = other.amount;
    scriptPubKey = other.scriptPubKey;
}
TransactionOutput &TransactionOutput::operator=(TransactionOutput const &other){ 
    amount = other.amount;
    scriptPubKey = other.scriptPubKey;
    return *this; 
};


// TODO: copy constructor, = operator
Transaction::Transaction(void){
    inputsNumber = 0;
    outputsNumber = 0;
}
Transaction::~Transaction(void){
    if(inputsNumber > 0){
        free(txIns);
    }
    if(outputsNumber > 0){
        free(txOuts);
    }
}
size_t Transaction::parse(Stream &s){
    if(inputsNumber > 0){
        free(txIns);
    }
    if(outputsNumber > 0){
        free(txOuts);
    }
    size_t len = 0;
    size_t l;
    uint8_t arr[4];
    len += s.readBytes(arr, 4);
    version = littleEndianToInt(arr, 4);
    if(len != 4){
        return 0;
    }

    // check if I can get inputs len (not with available() because of timeout)
    l = s.peek();
    if(l < 0){
        return 0;
    }
    inputsNumber = readVarInt(s);
    len += lenVarInt(inputsNumber);
    txIns = ( TransactionInput * )calloc( inputsNumber, sizeof(TransactionInput) );
    for(int i = 0; i < inputsNumber; i++){
        TransactionInput txIn;
        l = txIn.parse(s);
        txIns[i] = txIn;
        if(l == 0){
            return 0;
        }else{
            len += l;
        }
    }

    l = s.peek();
    if(l < 0){
        return 0;
    }
    outputsNumber = readVarInt(s);
    len += lenVarInt(outputsNumber);
    txOuts = ( TransactionOutput * )calloc( outputsNumber, sizeof(TransactionOutput) );
    for(int i = 0; i < outputsNumber; i++){
        TransactionOutput txOut;
        l = txOut.parse(s);
        txOuts[i] = txOut;
        if(l == 0){
            return 0;
        }else{
            len += l;
        }
    }

    l = s.readBytes(arr, 4);
    if(l != 4){
        return 0;
    }else{
        len += l;
    }
    locktime = littleEndianToInt(arr, 4);
    return len;
}

size_t Transaction::parse(byte raw[], size_t len){
    ByteStream s(raw, len);
    return parse(s);
}
uint8_t Transaction::addInput(TransactionInput txIn){
    inputsNumber ++;
    if(inputsNumber == 1){
        txIns = ( TransactionInput * )calloc( inputsNumber, sizeof(TransactionInput) );
    }else{
        txIns = ( TransactionInput * )realloc( txIns, inputsNumber * sizeof(TransactionInput) );
        memset(txIns+inputsNumber-1, 0, sizeof(TransactionInput));
    }
    txIns[inputsNumber-1] = txIn;
    return inputsNumber;
}
uint8_t Transaction::addOutput(TransactionOutput txOut){
    outputsNumber ++;
    if(outputsNumber == 1){
        txOuts = ( TransactionOutput * )calloc( outputsNumber, sizeof(TransactionOutput) );
    }else{
        txOuts = ( TransactionOutput * )realloc( txOuts, outputsNumber * sizeof(TransactionOutput) );
        memset(txOuts+outputsNumber-1, 0, sizeof(TransactionOutput));
    }
    txOuts[outputsNumber-1] = txOut;
    return outputsNumber;
}
size_t Transaction::length(){
    size_t len = 8 + lenVarInt(inputsNumber) + lenVarInt(outputsNumber); // version + locktime + inputsNumber + outputsNumber
    for(int i=0; i<inputsNumber; i++){
        len += txIns[i].length();
    }
    for(int i=0; i<outputsNumber; i++){
        len += txOuts[i].length();
    }
    return len;
}
size_t Transaction::serialize(Stream &s){
    uint8_t arr[4];
    size_t len = 0;
    intToLittleEndian(version, arr, 4);
    s.write(arr, 4);
    len += 4;
    writeVarInt(inputsNumber, s);
    len += lenVarInt(inputsNumber);
    for(int i=0; i<inputsNumber; i++){
        len += txIns[i].serialize(s);
    }
    writeVarInt(outputsNumber, s);
    len += lenVarInt(outputsNumber);
    for(int i=0; i<outputsNumber; i++){
        len += txOuts[i].serialize(s);
    }
    intToLittleEndian(locktime, arr, 4);
    s.write(arr, 4);
    len += 4;
    return len;
}
size_t Transaction::serialize(uint8_t array[], size_t len){
    if(len < length()){
        return 0;
    }
    size_t l = 0;
    intToLittleEndian(version, array, 4);
    l += 4;
    writeVarInt(inputsNumber, array+l, len-l);
    l += lenVarInt(inputsNumber);
    for(int i=0; i<inputsNumber; i++){
        l += txIns[i].serialize(array+l, len-l);
    }
    writeVarInt(outputsNumber, array+l, len-l);
    l += lenVarInt(outputsNumber);
    for(int i=0; i<outputsNumber; i++){
        l += txOuts[i].serialize(array+l, len-l);
    }
    intToLittleEndian(locktime, array+l, 4);
    l += 4;
    return l;
}

int Transaction::hash(uint8_t hash[32]){
    // TODO: refactor with stream hash functions
    ByteStream s;
    serialize(s);
    size_t len = s.available();
    uint8_t * arr;
    arr = (uint8_t *) calloc( len, sizeof(uint8_t));
    s.readBytes(arr, len);
    doubleSha(arr, len, hash);
    free(arr);
    return 0;
}
int Transaction::id(uint8_t id_arr[32]){
    uint8_t h[32] = { 0 };
    hash(h);
    for(int i=0; i<32; i++){ // flip
        id_arr[i] = h[31-i];
    }
    return 0;
}

int Transaction::sigHash(uint8_t inputIndex, Script scriptPubKey, uint8_t hash[32]){
    Script empty;
    ByteStream s;

    uint8_t arr[4];
    intToLittleEndian(version, arr, 4);
    s.write(arr, 4);
    writeVarInt(inputsNumber, s);
    for(int i=0; i<inputsNumber; i++){
        if(i != inputIndex){
            txIns[i].serialize(s, empty);
        }else{
            txIns[i].serialize(s, scriptPubKey);
        }
    }
    writeVarInt(outputsNumber, s);
    for(int i=0; i<outputsNumber; i++){
        txOuts[i].serialize(s);
    }
    intToLittleEndian(locktime, arr, 4);
    s.write(arr, 4);
    uint8_t sighash[] = {1,0,0,0}; // SIGHASH_ALL
    s.write(sighash, sizeof(sighash));

    size_t len = s.available();
    uint8_t * buf;
    buf = (uint8_t *) calloc( len, sizeof(uint8_t));
    s.readBytes(buf, len);
    doubleSha(buf, len, hash);
    free(buf);
    return 0;
}

Script Transaction::signInput(uint8_t inputIndex, PrivateKey pk){
    uint8_t h[32];
    PublicKey pubkey = pk.publicKey();
    sigHash(inputIndex, pubkey.script(), h);
    Signature sig = pk.sign(h);
    uint8_t der[80] = { 0 };
    size_t derLen = sig.der(der, sizeof(der));
    der[derLen] = 1;
    derLen++;

    uint8_t sec[65] = { 0 };
    size_t secLen = pubkey.sec(sec, sizeof(sec));

    uint8_t lenArr[2] = { secLen + derLen + 2, derLen };
    ByteStream s;
    s.write(lenArr, 2);
    s.write(der, derLen);
    s.write(secLen);
    s.write(sec, secLen);
    Script sc;
    sc.parse(s);
    txIns[inputIndex].scriptSig = sc;
    return sc;
}
