#include <Arduino.h>
#include "Bitcoin.h"
#include "Hash.h"
#include "Conversion.h"
#include "OpCodes.h"

Script::Script(void){}
Script::Script(uint8_t * buffer, size_t len){
	scriptLen = len;
    script = (uint8_t *) calloc( scriptLen, sizeof(uint8_t));
    memcpy(script, buffer, scriptLen);
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
