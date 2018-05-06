#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include "Bitcoin.h"
#include "Hash.h"
#include "BaseX.h"
#include "utility/micro-ecc/uECC.h"
#include "utility/sha256.h"
#include "utility/sha512.h"
#include "utility/segwit_addr.h"

// ---------------------------------------------------------------- Signature class

Signature::Signature(){}
Signature::Signature(byte r_arr[32], byte s_arr[32]){
    memcpy(r, r_arr, 32);
    memcpy(s, s_arr, 32);
}
// Signature::Signature(byte der[], size_t derLen){
//     memset(r, 0, 32);
//     memset(s, 0, 32);
//     if(derLen < 66){
//         return;
//     }
//     uint8_t rlen = der[3];
//     uint8_t slen = der[4+rlen+1];
//     uint8_t totlen = der[1];
//     if( (der[0] != 0x30) || 
//         (rlen > 33) || (rlen < 32) ||
//         (slen > 33) || (slen < 32) ||
//         (totlen != 2+rlen+2+slen) ||
//         (der[2] != 0x02) ||
//         (der[4+rlen] != 0x02)
//         ){
//         return;
//     }
//     memcpy(r, der+4+rlen-32, 32);
//     memcpy(s, der+4+rlen+2+slen-32, 32);
// }
Signature::Signature(byte der[]){
    memset(r, 0, 32);
    memset(s, 0, 32);
    uint8_t rlen = der[3];
    uint8_t slen = der[4+rlen+1];
    uint8_t totlen = der[1];
    if( (der[0] != 0x30) || 
        (rlen > 33) || (rlen < 32) ||
        (slen > 33) || (slen < 32) ||
        (totlen != 2+rlen+2+slen) ||
        (der[2] != 0x02) ||
        (der[4+rlen] != 0x02)
        ){
        return;
    }
    memcpy(r, der+4+rlen-32, 32);
    memcpy(s, der+4+rlen+2+slen-32, 32);
}

Signature::Signature(char der[]){
    byte sigRaw[75] = { 0 };
    byte v1 = hexToVal(der[2]);
    byte v2 = hexToVal(der[3]);
    if( (v1 > 0x0F) || (v2 > 0x0F) ){ // invalid chars
        Signature();
        return;
    }
    size_t derLen = (((v1 << 4) | v2)+2);
    int len = fromHex(der, 2*derLen, sigRaw, sizeof(sigRaw));
    if(len > 0){ // TODO: refactor, copypaste of above code
        memset(r, 0, 32);
        memset(s, 0, 32);
        uint8_t rlen = sigRaw[3];
        uint8_t slen = sigRaw[4+rlen+1];
        uint8_t totlen = sigRaw[1];
        if( (sigRaw[0] != 0x30) || 
            (rlen > 33) || (rlen < 32) ||
            (slen > 33) || (slen < 32) ||
            (totlen != 2+rlen+2+slen) ||
            (sigRaw[2] != 0x02) ||
            (sigRaw[4+rlen] != 0x02)
            ){
            return;
        }
        memcpy(r, sigRaw+4+rlen-32, 32);
        memcpy(s, sigRaw+4+rlen+2+slen-32, 32);    
    }else{
        Signature();
    }
}

size_t Signature::der(uint8_t * bytes, size_t len){
    memset(bytes, 0, len);
    bytes[0] = 0x30;
    // uint8_t totlen = 66;
    bytes[2] = 0x02;
    uint8_t rlen = 32;
    if(r[0] > 128){
        rlen = 33;
    }
    bytes[3] = rlen;
    memcpy(bytes+4+rlen-32, r, 32);
    bytes[4+rlen] = 0x02;
    uint8_t slen = 32;
    if(s[0] > 128){
        slen = 33;
    }
    bytes[4+rlen+1] = slen;
    memcpy(bytes+4+rlen+2+slen-32, s, 32);
    bytes[1] = 4+rlen+2+slen-2;
    return 4+rlen+2+slen;
}
void Signature::bin(byte arr[64]){
    memcpy(arr, r, 32);
    memcpy(arr+32, s, 32);
}
Signature::operator String(){ 
    uint8_t arr[70] = { 0 };
    int len = der(arr, sizeof(arr));
    return toHex(arr, len); 
};

// ---------------------------------------------------------------- PublicKey class
PublicKey::PublicKey(){}
PublicKey::PublicKey(uint8_t pubkeyArr[], bool use_compressed, bool use_testnet){
    memcpy(point, pubkeyArr, 64);
    compressed = use_compressed;
    testnet = use_testnet;
}
PublicKey::PublicKey(byte secArr[], bool use_testnet){
    testnet = use_testnet;
    memset(point, 0, 64);
    if(secArr[0]==0x04){
        compressed = false;
        memcpy(point, secArr+1, 64);
    }else{
        compressed = true;
        const struct uECC_Curve_t * curve = uECC_secp256k1();
        uECC_decompress(secArr, point, curve);
    }
}
PublicKey::PublicKey(char secHex[], bool use_testnet){
    testnet = use_testnet;
    memset(point, 0, 64);
    if((secHex[0] == '0') && (secHex[1] == '4')){
        compressed = false;
        fromHex(secHex+2, 2*64, point, 64);
    }else{
        compressed = true;
        byte secArr[33];
        fromHex(secHex, 2*33, secArr, 33);
        const struct uECC_Curve_t * curve = uECC_secp256k1();
        uECC_decompress(secArr, point, curve);
    }
}

int PublicKey::sec(uint8_t * sec, size_t len){
    // TODO: check length
    memset(sec, 0, len);
    if(compressed){
        sec[0] = 0x02 + (point[63] & 0x01);
        memcpy(sec+1, point, 32);
        return 33;
    }else{
        sec[0] = 0x04;
        memcpy(sec+1, point, 64);
        return 65;
    }
}
String PublicKey::sec(){
    uint8_t sec_arr[65] = { 0 };
    int len = sec(sec_arr, sizeof(sec_arr));
    return toHex(sec_arr, len);
}

int PublicKey::address(char * address, size_t len){
    memset(address, 0, len);

    uint8_t buffer[20];
    uint8_t sec_arr[65] = { 0 };
    int l = sec(sec_arr, sizeof(sec_arr));
    hash160(sec_arr, l, buffer);

    uint8_t addr[21];
    if(testnet){
        addr[0] = BITCOIN_TESTNET_P2PKH;
    }else{
        addr[0] = BITCOIN_MAINNET_P2PKH;
    }
    memcpy(addr+1, buffer, 20);

    return toBase58Check(addr, 21, address, len);
}
String PublicKey::address(){
    char addr[35] = { 0 };
    address(addr, sizeof(addr));
    return String(addr);
}
int PublicKey::segwitAddress(char address[], size_t len){
    memset(address, 0, len);
    if(len < 76){ // TODO: 76 is too much for native segwit
        return 0;
    }
    uint8_t hash[20];
    uint8_t sec_arr[65] = { 0 };
    int l = sec(sec_arr, sizeof(sec_arr));
    hash160(sec_arr, l, hash);
    char prefix[] = "bc";
    if(testnet){ // TODO: too ugly, refactor
        prefix[0] = 't';
        prefix[1] = 'b';
    }
    segwit_addr_encode(address, prefix, 0, hash, 20);
    return 76;
}
String PublicKey::segwitAddress(){
    char addr[76] = { 0 };
    segwitAddress(addr, sizeof(addr));
    return String(addr);
}
int PublicKey::nestedSegwitAddress(char address[], size_t len){
    memset(address, 0, len);
    uint8_t script[22] = { 0 };
    script[0] = 0x00;
    script[1] = 0x14;
    uint8_t sec_arr[65] = { 0 };
    int l = sec(sec_arr, sizeof(sec_arr));
    hash160(sec_arr, l, script+2);

    uint8_t addr[21];
    if(testnet){
        addr[0] = BITCOIN_TESTNET_P2SH;
    }else{
        addr[0] = BITCOIN_MAINNET_P2SH;
    }
    hash160(script, 22, addr+1);

    return toBase58Check(addr, 21, address, len);
}
String PublicKey::nestedSegwitAddress(){
    char addr[35] = { 0 };
    nestedSegwitAddress(addr, sizeof(addr));
    return String(addr);
}
bool PublicKey::verify(Signature sig, byte hash[32]){
    uint8_t signature[64] = {0};
    sig.bin(signature);
    const struct uECC_Curve_t * curve = uECC_secp256k1();
    return uECC_verify(point, hash, 32, signature, curve);
}
PublicKey::operator String(){ 
    uint8_t arr[65] = { 0 };
    int len = sec(arr, sizeof(arr));
    return toHex(arr, len); 
};
bool PublicKey::isValid(){
    const struct uECC_Curve_t * curve = uECC_secp256k1();
    return uECC_valid_public_key(point, curve);
}

// ---------------------------------------------------------------- PrivateKey class
PrivateKey::PrivateKey(void){
    memset(secret, 0xFF, 32); // empty key
}
PrivateKey::PrivateKey(uint8_t secret_arr[], bool use_compressed, bool use_testnet){
    memcpy(secret, secret_arr, 32);
    compressed = use_compressed;
    testnet = use_testnet;

    const struct uECC_Curve_t * curve = uECC_secp256k1();
    uint8_t p[64] = {0};
    uECC_compute_public_key(secret, p, curve);
    pubKey = PublicKey(p, use_compressed, use_testnet);
}
PrivateKey::~PrivateKey(void) {
    // erase secret key from memory
    memset(secret, 0, 32);
}

int PrivateKey::wif(char wifArr[], size_t wifSize){
    memset(wifArr, 0, wifSize);

    uint8_t wifHex[34] = { 0 }; // prefix + 32 bytes secret (+ compressed )
    size_t len = 33;
    if(testnet){
        wifHex[0] = BITCOIN_TESTNET_PREFIX;
    }else{
        wifHex[0] = BITCOIN_MAINNET_PREFIX;
    }
    memcpy(wifHex+1, secret, 32);
    if(compressed){
        wifHex[33] = 0x01;
        len++;
    }
    size_t l = toBase58Check(wifHex, len, wifArr, wifSize);

    memset(wifHex, 0, sizeof(wifHex)); // secret should not stay in RAM
    return l;
}
String PrivateKey::wif(){
    char wifString[53] = { 0 };
    wif(wifString, sizeof(wifString));
    return String(wifString);
}
int PrivateKey::fromWIF(const char wifArr[], size_t wifSize){
    byte arr[40] = { 0 };
    size_t l = fromBase58Check(wifArr, wifSize, arr, sizeof(arr));
    if( (l < 33) || (l > 34) ){
        memset(secret, 0xFF, 32);
        return 1;// TODO: ERROR CODES
    }
    // TODO: refactor for different networks (Litecoin etc)
    testnet = (arr[0] != BITCOIN_MAINNET_PREFIX);
    if(l == 34){
        compressed = (arr[33] > 0);
    }
    if(l == 33){
        compressed = false;
    }
    memcpy(secret, arr+1, 32);
    memset(arr, 0, 40); // clear memory

    // TODO: incapsulate
    const struct uECC_Curve_t * curve = uECC_secp256k1();
    uint8_t p[64] = {0};
    uECC_compute_public_key(secret, p, curve);
    pubKey = PublicKey(p, compressed, testnet);

    return 0;
}
int PrivateKey::fromWIF(const char wifArr[]){
    return fromWIF(wifArr, strlen(wifArr));
}
// TODO: check if > N ???
bool PrivateKey::isValid(){
    bool valid = false;
    for(int i=0; i<31; i++){
        if(secret[i] != 0xFF){
            valid = true;
        }
    }
    return valid;
}

PublicKey PrivateKey::publicKey(){
    pubKey.testnet = testnet;
    pubKey.compressed = compressed;
    return pubKey;
}

int PrivateKey::address(char * address, size_t len){
    return publicKey().address(address, len);
}
String PrivateKey::address(){
    return publicKey().address();
}
int PrivateKey::segwitAddress(char * address, size_t len){
    return publicKey().segwitAddress(address, len);
}
String PrivateKey::segwitAddress(){
    return publicKey().segwitAddress();
}
int PrivateKey::nestedSegwitAddress(char * address, size_t len){
    return publicKey().nestedSegwitAddress(address, len);
}
String PrivateKey::nestedSegwitAddress(){
    return publicKey().nestedSegwitAddress();
}


Signature PrivateKey::sign(byte hash[32]){
    uint8_t tmp[32 + 32 + 64] = {0};
    uint8_t signature[64] = {0};
    const struct uECC_Curve_t * curve = uECC_secp256k1();

    SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
    int result = uECC_sign_deterministic(secret, hash, 32, &ctx.uECC, signature, curve);
    Signature sig(signature, signature+32);
    return sig;
}

// TODO: refactor with memcmp
bool PrivateKey::operator==(const PrivateKey& other) const{
    for(int i = 0; i < 32; i++){
        if(secret[i] != other.secret[i]){
            return false;
        }
    }
    return (testnet == other.testnet) && (compressed == other.compressed);
}
// secret > N can be used for codes like EMPTY_KEY, INVALID_KEY etc
bool PrivateKey::operator==(const int& other) const{
    for(int i = 0; i < 31; i++){
        if(secret[i] != 0xFF){
            return false;
        }
    }
    return (0xFF-secret[31])==other;
}
bool PrivateKey::operator!=(const PrivateKey& other) const{
    return !operator==(other);
}
bool PrivateKey::operator!=(const int& other) const{
    return !operator==(other);
}
PrivateKey::PrivateKey(const char wifArr[]){
    fromWIF(wifArr);
}
PrivateKey::PrivateKey(const String wifString){
    char * ch;
    int len = wifString.length()+1;
    ch = (char *) malloc(len);
    memset(ch, 0, len);
    wifString.toCharArray(ch, len);
    fromWIF(ch);
    free(ch);
}

// ---------------------------------------------------------------- HDPrivateKey class
// TODO: make friends with PrivateKey to get secret or inherit from it
HDPrivateKey::HDPrivateKey(void){
    privateKey.compressed = true;
    memset(chainCode, 0, 32);
    depth = 0;
    memset(fingerprint, 0, 4);
    childNumber = 0;
}
HDPrivateKey::HDPrivateKey(uint8_t secret[32], uint8_t chain_code[32], bool use_testnet){
    privateKey = PrivateKey(secret, true, use_testnet);
    memcpy(chainCode, chain_code, 32);
}
HDPrivateKey::HDPrivateKey(char xprvArr[]){
    size_t xprvLen = strlen(xprvArr);
    byte arr[85] = { 0 };
    size_t l = fromBase58Check(xprvArr, xprvLen, arr, sizeof(arr));
    //     uint8_t prefix[] = { 0x04, 0x35, 0x83, 0x94};
    //     memcpy(hex, prefix, 4);
    // }else{
    //     uint8_t prefix[] = { 0x04, 0x88, 0xAD, 0xE4};
    //     memcpy(hex, prefix, 4);

}
HDPrivateKey::~HDPrivateKey(void) {
    // erase chain code from memory
    memset(chainCode, 0, 32);
    // privateKey will clean everything up by itself
}
int HDPrivateKey::fromSeed(uint8_t seed[64], bool use_testnet){
    uint8_t raw[64] = { 0 };
    SHA512 sha;
    char key[] = "Bitcoin seed";
    sha.resetHMAC(key, strlen(key));
    sha.update(seed, 64);
    sha.finalizeHMAC(key, strlen(key), raw, sizeof(raw));
    // sha512Hmac((byte *)key, strlen(key), seed, 64, raw);
    privateKey = PrivateKey(raw, true, use_testnet);
    memcpy(chainCode, raw+32, 32);
}
int HDPrivateKey::fromMnemonic(char mnemonic[], char password[], bool use_testnet){
    uint8_t seed[64] = { 0 };
    uint8_t ind[4] = { 0, 0, 0, 1 };
    char salt[] = "mnemonic";
    uint8_t u[64] = { 0 };

    // first round
    SHA512 sha;
    sha.resetHMAC(mnemonic, strlen(mnemonic));
    sha.update(salt, strlen(salt));
    sha.update(password, strlen(password));
    sha.update(ind, sizeof(ind));
    sha.finalizeHMAC(mnemonic, strlen(mnemonic), u, sizeof(u));
    memcpy(seed, u, 64);
    // other rounds
    for(int i=1; i<PBKDF2_ROUNDS; i++){
        sha.resetHMAC(mnemonic, strlen(mnemonic));
        sha.update(u, sizeof(u));
        sha.finalizeHMAC(mnemonic, strlen(mnemonic), u, sizeof(u));
        for(int j=0; j<sizeof(seed); j++){
            seed[j] = seed[j] ^ u[j];
        }
    }
    fromSeed(seed, use_testnet);
}
bool HDPrivateKey::isValid(){
    return privateKey.isValid();
}
String HDPrivateKey::xprv(){
    char result[120] = { 0 };
    uint8_t hex[78] = { 0 };
    if(privateKey.testnet){
        uint8_t prefix[] = { 0x04, 0x35, 0x83, 0x94};
        memcpy(hex, prefix, 4);
    }else{
        uint8_t prefix[] = { 0x04, 0x88, 0xAD, 0xE4};
        memcpy(hex, prefix, 4);
    }
    hex[4] = depth;
    memcpy(hex+5, fingerprint, 4);
    for(uint8_t i=0; i<4; i++){
        hex[12-i] = ((childNumber >> (i*8)) & 0xFF);
    }
    memcpy(hex+13, chainCode, 32);
    memcpy(hex+46, privateKey.secret, 32);
    size_t l = toBase58Check(hex, sizeof(hex), result, sizeof(result));
    return String(result);
}
String HDPrivateKey::xpub(){
    char result[180] = { 0 };
    uint8_t hex[111] = { 0 };
    if(privateKey.testnet){
        uint8_t prefix[] = { 0x04, 0x35, 0x87, 0xCF};
        memcpy(hex, prefix, 4);
    }else{
        uint8_t prefix[] = { 0x04, 0x88, 0xB2, 0x1E};
        memcpy(hex, prefix, 4);
    }
    hex[4] = depth;
    memcpy(hex+5, fingerprint, 4);
    for(uint8_t i=0; i<4; i++){
        hex[12-i] = ((childNumber >> (i*8)) & 0xFF);
    }
    memcpy(hex+13, chainCode, 32);

    uint8_t sec[65] = { 0 };
    int secLen = privateKey.publicKey().sec(sec, sizeof(sec));
    memcpy(hex+45, sec, secLen);
    size_t l = toBase58Check(hex, 45+secLen, result, sizeof(result));
    return String(result);
}
// TODO: refactor to single function!
HDPrivateKey HDPrivateKey::child(uint32_t index){
    HDPrivateKey child;

    uint8_t sec[65] = { 0 };
    int l = privateKey.publicKey().sec(sec, sizeof(sec));
    uint8_t hash[20] = { 0 };
    hash160(sec, l, hash);
    memcpy(child.fingerprint, hash, 4);
    child.childNumber = index;
    child.depth = depth+1;

    uint8_t data[69];
    memcpy(data, sec, l);
    for(uint8_t i=0; i<4; i++){
        data[l+3-i] = ((index >> (i*8)) & 0xFF);
    }

    uint8_t raw[64];
    SHA512 sha;
    sha.resetHMAC(chainCode, sizeof(chainCode));
    sha.update(data, l+4);
    sha.finalizeHMAC(chainCode, sizeof(chainCode), raw, sizeof(raw));

    memcpy(child.chainCode, raw+32, 32);

    uint16_t carry = 0;
    uint8_t res[32] = { 0 };
    // TODO: test it!!!
    // refactor with uECC_vli.h
    for(int i=31; i>=0; i--){
        carry += raw[i];
        carry += privateKey.secret[i];
        res[i] = (carry & 0xFF);
        carry >>= 8;
    }
    bool gtn = false; // if greater then N
    uint8_t N[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    if(carry>0){
        gtn = true;
    }else{
        for(int i=0; i<32; i++){
            if(res[i] > N[i]){
                gtn = true;
            }
            if(res[i] < N[i]){
                break;
            }
        }
    }
    if(gtn == true){
        // remove minusN, make (0xFF-N[i]) instead
        uint8_t minusN[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
            0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 
            0x40, 0x2d, 0xa1, 0x73, 0x2f, 0xc9, 0xbe, 0xbf
        };
        carry = 0;
        for(int i=31; i>=0; i--){
            carry += (uint16_t)minusN[i] + res[i];
            res[i] = (0xFF & carry);
            carry >>= 8;
        }
    }
    child.privateKey = PrivateKey(res, true, privateKey.testnet);
    memset(res, 0, 32);
    return child;
}
HDPrivateKey HDPrivateKey::hardenedChild(uint32_t index){
    // TODO: refactor, the same used in two functions
    HDPrivateKey child;

    uint8_t sec[65] = { 0 };
    int l = privateKey.publicKey().sec(sec, sizeof(sec));
    uint8_t hash[20] = { 0 };
    hash160(sec, l, hash);
    memcpy(child.fingerprint, hash, 4);
    index += (1<<31);
    child.childNumber = index;
    child.depth = depth+1;

    uint8_t data[37] = { 0 };
    memcpy(data+1, privateKey.secret, 32);
    for(uint8_t i=0; i<4; i++){
        data[36-i] = ((index >> (i*8)) & 0xFF);
    }

    uint8_t raw[64];
    SHA512 sha;
    sha.resetHMAC(chainCode, sizeof(chainCode));
    sha.update(data, sizeof(data));
    sha.finalizeHMAC(chainCode, sizeof(chainCode), raw, sizeof(raw));

    memcpy(child.chainCode, raw+32, 32);

    uint16_t carry = 0;
    uint8_t res[32] = { 0 };
    // TODO: test it!!!
    // refactor with uECC_vli.h
    for(int i=31; i>=0; i--){
        carry += raw[i];
        carry += privateKey.secret[i];
        res[i] = (carry & 0xFF);
        carry >>= 8;
    }
    bool gtn = false; // if greater then N
    uint8_t N[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    if(carry>0){
        gtn = true;
    }else{
        for(int i=0; i<32; i++){
            if(res[i] > N[i]){
                gtn = true;
            }
            if(res[i] < N[i]){
                break;
            }
        }
    }
    if(gtn == true){
        // remove minusN, make (0xFF-N[i]) instead
        uint8_t minusN[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
            0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 
            0x40, 0x2d, 0xa1, 0x73, 0x2f, 0xc9, 0xbe, 0xbf
        };
        carry = 0;
        for(int i=31; i>=0; i--){
            carry += (uint16_t)minusN[i] + res[i];
            res[i] = (0xFF & carry);
            carry >>= 8;
        }
    }
    child.privateKey = PrivateKey(res, true, privateKey.testnet);
    memset(res, 0, 32);
    return child;
}

