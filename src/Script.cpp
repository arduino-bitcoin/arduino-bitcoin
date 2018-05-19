#include <Arduino.h>
#include "Bitcoin.h"
#include "Hash.h"
#include "Conversion.h"
#include "OpCodes.h"
#include "utility/segwit_addr.h"

Script::Script(void){
    scriptLen = 0;
    script = NULL;
}
Script::Script(uint8_t * buffer, size_t len){
	scriptLen = len;
    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    memcpy(script, buffer, scriptLen);
}
Script::Script(char * address){
    uint8_t addr[21];
    size_t len = strlen(address);
    if(len > 100){ // very wrong address
        return;
    }
    // segwit
    if((memcmp(address,"bc", 2) == 0) || (memcmp(address,"tb", 2) == 0)){
        int ver = 0;
        uint8_t prog[32];
        size_t prog_len = 0;
        char hrp[] = "bc";
        memcpy(hrp, address, 2);
        int r = segwit_addr_decode(&ver, prog, &prog_len,hrp, address);
        if(r != 1){ // decoding failed
            return;
        }
        scriptLen = prog_len + 2;
        script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
        script[0] = ver;
        script[1] = prog_len; // varint?
        memcpy(script+2, prog, prog_len);
    }else{ // legacy or nested segwit
        int l = fromBase58Check(address, len, addr, sizeof(addr));
        if(l != 21){ // either wrong checksum or wierd address
            return;
        }
        if((addr[0] == BITCOIN_MAINNET_P2PKH) || (addr[0] == BITCOIN_TESTNET_P2PKH)){
            scriptLen = 25;
            script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
            script[0] = OP_DUP;
            script[1] = OP_HASH160;
            script[2] = 20;
            memcpy(script+3, addr+1, 20);
            script[23] = OP_EQUALVERIFY;
            script[24] = OP_CHECKSIG;
        }
        if((addr[0] == BITCOIN_MAINNET_P2SH) || (addr[0] == BITCOIN_TESTNET_P2SH)){
            scriptLen = 23;
            script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
            script[1] = OP_HASH160;
            script[2] = 20;
            memcpy(script+2, addr+1, 20);
            script[22] = OP_EQUAL;
        }
    }
}
Script::Script(PublicKey pubkey, int type){
    if(type == P2PKH){
    	scriptLen = 25;
    	script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 20;
        uint8_t sec_arr[65] = { 0 };
        int l = pubkey.sec(sec_arr, sizeof(sec_arr));
        hash160(sec_arr, l, script+3);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;
    }
}
Script::Script(Script const &other){
    if(other.scriptLen > 0){
		scriptLen = other.scriptLen;
        script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
        memcpy(script, other.script, scriptLen);
    }
}
Script::~Script(void){
	clear();
}
size_t Script::parse(Stream &s){
	clear();
    int l = s.peek();
    if(l < 0){
        return 0;
    }
    scriptLen = readVarInt(s);
    size_t len = lenVarInt(scriptLen);

    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    len += s.readBytes(script, scriptLen);
    return len;
}
int Script::type(){
	if(
		(scriptLen == 25) && 
		(script[0] == OP_DUP) &&
		(script[1] == OP_HASH160) &&
		(script[2] == 20) &&
		(script[23] == OP_EQUALVERIFY) &&
		(script[24] == OP_CHECKSIG)
	){
		return P2PKH;
	}
    if(
        (scriptLen == 23) &&
        (script[0] == OP_HASH160) &&
        (script[1] == 20) &&
        (script[22] == OP_EQUAL)
    ){
        return P2SH;
    }
    if(
        (scriptLen == 22) &&
        (script[0] == 0x00) &&
        (script[1] == 20)
    ){
        return P2WPKH;
    }
    if(
        (scriptLen == 34) &&
        (script[0] == 0x00) &&
        (script[1] == 32)
    ){
        return P2WSH;
    }
	return 0;
}
String Script::address(bool testnet){
	if(type() == P2PKH){
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
	}
    if(type() == P2SH){
        uint8_t addr[21];
        if(testnet){
            addr[0] = BITCOIN_TESTNET_P2SH;
        }else{
            addr[0] = BITCOIN_MAINNET_P2SH;
        }
        memcpy(addr+1, script + 2, 20);
        char address[40] = { 0 };
        toBase58Check(addr, 21, address, sizeof(address));
        return String(address);
    }
    if(type() == P2WPKH || type() == P2WSH){
        char address[76] = { 0 };
        char prefix[] = "bc";
        if(testnet){
            memcpy(prefix, "tb", 2);
        }
        segwit_addr_encode(address, prefix, script[0], script+2, script[1]);
        return String(address);
    }
	return "Unknown address";
}
void Script::clear(){
	if(scriptLen > 0){
		free(script);
		scriptLen = 0;
	}
}
size_t Script::length(){
    return scriptLen + lenVarInt(scriptLen);
}
size_t Script::serialize(Stream &s){
    size_t len = 0;
    writeVarInt(scriptLen, s);
    s.write(script, scriptLen);
    return length();
}
size_t Script::serialize(uint8_t array[], size_t len){
    if(len < length()){
        return 0;
    }
    size_t l = lenVarInt(scriptLen);
    writeVarInt(scriptLen, array, len);
    memcpy(array+l, script, scriptLen);
    return length();
}
size_t Script::push(uint8_t code){
    if(scriptLen == 0){
        scriptLen = 1;
        script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    }else{
        scriptLen ++;
        script = (uint8_t *) realloc( script, scriptLen * sizeof(uint8_t));
    }
    script[scriptLen-1] = code;
    return scriptLen;
}
size_t Script::push(uint8_t * data, size_t len){
    if(scriptLen == 0){
        script = (uint8_t *) calloc( len, sizeof(uint8_t));
    }else{
        script = (uint8_t *) realloc( script, (scriptLen + len) * sizeof(uint8_t));
    }
    memcpy(script + scriptLen, data, len);
    scriptLen += len;
    return scriptLen;
}
size_t Script::push(PublicKey pubkey){
    uint8_t sec[65];
    uint8_t len = pubkey.sec(sec, sizeof(sec));
    push(len);
    push(sec, len);
    return scriptLen;
}
size_t Script::push(Signature sig){//, uint8_t sigType){
    uint8_t der[75];
    uint8_t len = sig.der(der, sizeof(der));
    push(len+1);
    push(der, len);
    // push(sigType);
    push(SIGHASH_ALL);
    return scriptLen;
}
size_t Script::push(Script sc){
    uint8_t len = sc.length();
    uint8_t * tmp;
    tmp = (uint8_t *)calloc(len, sizeof(uint8_t));
    sc.serialize(tmp, len);
    push(tmp, len);
    return scriptLen;
}

Script Script::scriptPubkey(){
    Script sc;
    uint8_t h[20];
    hash160(script, scriptLen, h);
    sc.push(OP_HASH160);
    sc.push(20);
    sc.push(h, 20);
    sc.push(OP_EQUAL);
    return sc;
}

Script &Script::operator=(Script const &other){ 
    clear();
    if(other.scriptLen > 0){
		scriptLen = other.scriptLen;
        script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
        memcpy(script, other.script, scriptLen);
    }
    return *this; 
};

Script::operator String(){ 
	if(scriptLen>0){
	    return toHex(script, scriptLen);
	}else{
		return "";
	}
};
