#include <Arduino.h>
#include "Bitcoin.h"
#include "Hash.h"
#include "Conversion.h"
#include "OpCodes.h"

Script::Script(void){}
Script::Script(uint8_t * buffer, size_t len){
	length = len;
    script = (uint8_t *) calloc( length, sizeof(uint8_t));
    memcpy(script, buffer, length);
}
Script::Script(Script const &other){
    if(other.length > 0){
		length = other.length;
        script = (uint8_t *) calloc( length, sizeof(uint8_t));
        memcpy(script, other.script, length);
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
    // TODO: varint!!!
    length = s.read();
    size_t len = 1;

    script = (uint8_t *) calloc( length, sizeof(uint8_t));
    len += s.readBytes(script, length);
    return len;
}
int Script::type(){
	if(
		(length == 25) && 
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
	if(length > 0){
		free(script);
		length = 0;
	}
}
Script &Script::operator=(Script const &other){ 
    clear();
    if(other.length > 0){
		length = other.length;
        script = (uint8_t *) calloc( length, sizeof(uint8_t));
        memcpy(script, other.script, length);
    }
    return *this; 
};

Script::operator String(){ 
	if(length>0){
	    return toHex(script, length);
	}else{
		return "";
	}
};
