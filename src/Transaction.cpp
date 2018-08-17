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
TransactionInput::TransactionInput(char prev_id_hex[], uint32_t prev_index){
    Script script;
    uint32_t sequence_number = 0xffffffff;
    uint8_t prev_id[32];
    fromHex(prev_id_hex, prev_id, sizeof(prev_id));
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
bool TransactionInput::isSegwit(){
    int type = scriptPubKey.type();
    if((type == P2WPKH) || (type == P2WSH)){
        return true;
    }
    return (witnessProgram.length() > 1);
}
TransactionInput::TransactionInput(TransactionInput const &other){
    memcpy(hash, other.hash, 32);
    outputIndex = other.outputIndex;
    scriptSig = other.scriptSig;
    sequence = other.sequence;
    witnessProgram = other.witnessProgram;
    amount = other.amount;
    scriptPubKey = other.scriptPubKey;
}
TransactionInput &TransactionInput::operator=(TransactionInput const &other){ 
    memcpy(hash, other.hash, 32);
    outputIndex = other.outputIndex;
    scriptSig = other.scriptSig;
    sequence = other.sequence;
    witnessProgram = other.witnessProgram;
    amount = other.amount;
    scriptPubKey = other.scriptPubKey;
    return *this; 
};
TransactionInput::operator String(){ 
    size_t len = length();
    uint8_t * ser;
    ser = (uint8_t *)calloc(len, sizeof(uint8_t));
    serialize(ser, len);
    String s = toHex(ser, len);
    free(ser);
    return s;
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
TransactionOutput::TransactionOutput(uint64_t send_amount, String address){
    amount = send_amount;
    Script sc(address);
    scriptPubKey = sc;
}
TransactionOutput::TransactionOutput(Script outputScript, uint64_t send_amount){
    amount = send_amount;
    scriptPubKey = outputScript;
}
TransactionOutput::TransactionOutput(char address[], uint64_t send_amount){
    amount = send_amount;
    Script sc(address);
    scriptPubKey = sc;
}
TransactionOutput::TransactionOutput(String address, uint64_t send_amount){
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
TransactionOutput::operator String(){ 
    size_t len = length();
    uint8_t * ser;
    ser = (uint8_t *)calloc(len, sizeof(uint8_t));
    serialize(ser, len);
    String s = toHex(ser, len);
    free(ser);
    return s;
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
Transaction::Transaction(Transaction const &other){
    // TODO: just serialize() and parse()
    version = other.version;
    locktime = other.locktime;
    inputsNumber = other.inputsNumber;
    txIns = (TransactionInput *) calloc( inputsNumber, sizeof(TransactionInput));
    for(int i=0; i<inputsNumber; i++){
        txIns[i] = other.txIns[i];
    }
    outputsNumber = other.outputsNumber;
    txOuts = (TransactionOutput *) calloc( outputsNumber, sizeof(TransactionOutput));
    for(int i=0; i<outputsNumber; i++){
        txOuts[i] = other.txOuts[i];
    }
}
Transaction &Transaction::operator=(Transaction const &other){ 
    version = other.version;
    locktime = other.locktime;
    inputsNumber = other.inputsNumber;
    txIns = (TransactionInput *) calloc( inputsNumber, sizeof(TransactionInput));
    for(int i=0; i<inputsNumber; i++){
        txIns[i] = other.txIns[i];
    }
    outputsNumber = other.outputsNumber;
    txOuts = (TransactionOutput *) calloc( outputsNumber, sizeof(TransactionOutput));
    for(int i=0; i<outputsNumber; i++){
        txOuts[i] = other.txOuts[i];
    }
    return *this; 
};
size_t Transaction::parse(Stream &s){
    bool is_segwit = false;
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
    l = s.peek(); // do I need all this stuff?
    if(l < 0){
        return 0;
    }
    if(l == 0x00){ // segwit marker
        uint8_t marker = s.read();
        uint8_t flag = s.read();
        len += 2;
        if(flag != 0x01){
            return 0; // wrong segwit flag
        }
        is_segwit = true;
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

    if(is_segwit){
        for(int i=0; i<inputsNumber; i++){
            Script witness_program;
            size_t numElements = readVarInt(s);
            uint8_t arr[9];
            uint8_t l = writeVarInt(numElements, arr, sizeof(arr));
            witness_program.push(arr, l);
            for(int j = 0; j < numElements; j++){
                Script element;
                element.parse(s);
                witness_program.push(element);
            }
            txIns[i].witnessProgram = witness_program;
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
bool Transaction::isSegwit(){
    for(int i=0; i<inputsNumber; i++){
        if(txIns[i].isSegwit()){
            return true;
        }
    }
    return false;
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
    if(isSegwit()){
        len += 2; // marker + flag
        for(int i=0; i<inputsNumber; i++){
            len += txIns[i].witnessProgram.scriptLength();
        }
    }
    return len;
}
size_t Transaction::serialize(Stream &s, bool segwit){
    uint8_t arr[4];
    size_t len = 0;
    intToLittleEndian(version, arr, 4);
    s.write(arr, 4);
    len += 4;
    if(segwit){
        len += 2;
        uint8_t arr[2] = { 0, 1 };
        s.write(arr, 2); // marker + flag
    }
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
    if(segwit){
        for(int i=0; i<inputsNumber; i++){
            txIns[i].witnessProgram.serializeScript(s);
            len += txIns[i].witnessProgram.scriptLength();
        }
    }
    intToLittleEndian(locktime, arr, 4);
    s.write(arr, 4);
    len += 4;
    return len;    
}
size_t Transaction::serialize(Stream &s){
    bool is_segwit = isSegwit();
    return serialize(s, is_segwit);
}
size_t Transaction::serialize(uint8_t array[], size_t len){
    ByteStream s;
    serialize(s);
    if(s.available() > len){
        return 0;
    }
    size_t l = s.available();
    s.readBytes(array, l);
    return l;
}

int Transaction::hash(uint8_t hash[32]){
    // TODO: refactor with stream hash functions
    ByteStream s;
    serialize(s, false);
    size_t len = s.available();
    uint8_t * arr;
    arr = (uint8_t *) calloc( len, sizeof(uint8_t));
    s.readBytes(arr, len);
    doubleSha(arr, len, hash);
    free(arr);
    return 0;
}

int Transaction::id(uint8_t id_arr[32]){
    uint8_t h[32];
    hash(h);
    for(int i=0; i<32; i++){ // flip
        id_arr[i] = h[31-i];
    }
    return 0;
}
String Transaction::id(){
    uint8_t id_arr[32];
    id(id_arr);
    return toHex(id_arr, 32);
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

int Transaction::hashPrevouts(uint8_t hash[32]){
    ByteStream s;
    for(int i=0; i<inputsNumber; i++){
        s.write(txIns[i].hash, 32);
        uint8_t arr[4];
        intToLittleEndian(txIns[i].outputIndex, arr, 4);
        s.write(arr, 4);
    }
    size_t len = s.available();
    uint8_t * buf;
    buf = (uint8_t *) calloc( len, sizeof(uint8_t));
    s.readBytes(buf, len);
    doubleSha(buf, len, hash);
    free(buf);
    return 0;
}

int Transaction::hashSequence(uint8_t hash[32]){
    ByteStream s;
    for(int i=0; i<inputsNumber; i++){
        uint8_t arr[4];
        intToLittleEndian(txIns[i].sequence, arr, 4);
        s.write(arr, 4);
    }
    size_t len = s.available();
    uint8_t * buf;
    buf = (uint8_t *) calloc( len, sizeof(uint8_t));
    s.readBytes(buf, len);
    doubleSha(buf, len, hash);
    free(buf);
    return 0;
}

int Transaction::hashOutputs(uint8_t hash[32]){
    ByteStream s;
    for(int i=0; i<outputsNumber; i++){
        txOuts[i].serialize(s);
    }
    size_t len = s.available();
    uint8_t * buf;
    buf = (uint8_t *) calloc( len, sizeof(uint8_t));
    s.readBytes(buf, len);
    doubleSha(buf, len, hash);
    free(buf);
    return 0;
}

int Transaction::sigHashSegwit(uint8_t inputIndex, Script scriptPubKey, uint8_t hash[32]){
    ByteStream s;
    uint8_t arr[8];
    intToLittleEndian(version, arr, 4);
    s.write(arr, 4);

    uint8_t h[32];
    hashPrevouts(h);
    s.write(h, 32);
    hashSequence(h);
    s.write(h, 32);

    s.write(txIns[inputIndex].hash, 32);
    intToLittleEndian(txIns[inputIndex].outputIndex, arr, 4);
    s.write(arr, 4);
    scriptPubKey.serialize(s);

    intToLittleEndian(txIns[inputIndex].amount, arr, 8);
    s.write(arr, 8);
    intToLittleEndian(txIns[inputIndex].sequence, arr, 4);
    s.write(arr, 4);

    hashOutputs(h);
    s.write(h, 32);

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

Signature Transaction::signInput(uint8_t inputIndex, PrivateKey pk, Script redeemScript){
    uint8_t h[32];
    int type = redeemScript.type();
    bool is_segwit = (isSegwit()) || (type == P2WPKH) || (type == P2WSH);
    if(is_segwit){
        if((type == P2WPKH) || (type == P2WSH)){
            Script script_pubkey(pk.publicKey()); // TODO: make it based on redeemScript
            sigHashSegwit(inputIndex, script_pubkey, h);
        }else{
            sigHashSegwit(inputIndex, redeemScript, h);
        }
    }else{
        sigHash(inputIndex, redeemScript, h);
    }
    PublicKey pubkey = pk.publicKey();
    Signature sig = pk.sign(h);
    uint8_t der[80] = { 0 };
    size_t derLen = sig.der(der, sizeof(der));
    der[derLen] = 1;
    derLen++;

    uint8_t sec[65] = { 0 };
    size_t secLen = pubkey.sec(sec, sizeof(sec));

    if(is_segwit){
        if((type == P2WPKH) || (type == P2WSH)){
            Script script_sig;
            script_sig.push(redeemScript);
            txIns[inputIndex].scriptSig = script_sig;
        }else{
            Script empty;
            txIns[inputIndex].scriptSig = empty;
        }

        uint8_t lenArr[3] = { secLen + derLen + 3, 2, derLen };
        ByteStream s;
        s.write(lenArr, 3);
        s.write(der, derLen);
        s.write(secLen);
        s.write(sec, secLen);
        Script sc;
        sc.parse(s);
        txIns[inputIndex].witnessProgram = sc;
    }else{
        uint8_t lenArr[2] = { secLen + derLen + 2, derLen };
        ByteStream s;
        s.write(lenArr, 2);
        s.write(der, derLen);
        s.write(secLen);
        s.write(sec, secLen);
        Script sc;
        sc.parse(s);
        txIns[inputIndex].scriptSig = sc;
    }
    return sig;
}

Signature Transaction::signInput(uint8_t inputIndex, PrivateKey pk){
    PublicKey pubkey = pk.publicKey();
    return signInput(inputIndex, pk, pubkey.script());
}
Transaction::operator String(){ 
    size_t len = length();
    uint8_t * ser;
    ser = (uint8_t *)calloc(len, sizeof(uint8_t));
    serialize(ser, len);
    String s = toHex(ser, len);
    free(ser);
    return s;
};