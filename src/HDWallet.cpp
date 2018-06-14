#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include "Bitcoin.h"
#include "Hash.h"
#include "Conversion.h"
#include "utility/micro-ecc/uECC.h"
#include "utility/sha256.h"
#include "utility/sha512.h"
#include "utility/segwit_addr.h"

// ---------------------------------------------------------------- HDPrivateKey class

// TODO: add yprv, zprv, uprv, vprv and store address type:
// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
// useful tool: in https://iancoleman.io/bip39/
// Bitcoin 0x0488b21e - xpub   0x0488ade4 - xprv   P2PKH or P2SH
// Bitcoin 0x049d7cb2 - ypub   0x049d7878 - yprv   P2WPKH in P2SH
// Bitcoin 0x0295b43f - Ypub   0x0295b005 - Yprv   P2WSH in P2SH
// Bitcoin 0x04b24746 - zpub   0x04b2430c - zprv   P2WPKH
// Bitcoin 0x02aa7ed3 - Zpub   0x02aa7a99 - Zprv   P2WSH
// Bitcoin Testnet 0x043587cf - tpub   0x04358394 - tprv   P2PKH or P2SH
// Bitcoin Testnet 0x044a5262 - upub   0x044a4e28 - uprv   P2WPKH in P2SH
// Bitcoin Testnet 0x045f1cf6 - vpub   0x045f18bc - vprv   P2WPKH
// Bitcoin Testnet 0x02575483 - Vpub   0x02575048 - Vprv   P2WSH

uint8_t XPUB_MAINNET_PREFIX[4] = { 0x04, 0x88, 0xB2, 0x1E };
uint8_t XPRV_MAINNET_PREFIX[4] = { 0x04, 0x88, 0xAD, 0xE4 };

uint8_t XPUB_TESTNET_PREFIX[4] = { 0x04, 0x35, 0x87, 0xCF };
uint8_t XPRV_TESTNET_PREFIX[4] = { 0x04, 0x35, 0x83, 0x94 };

// TODO: make friends with PrivateKey to get secret or inherit from it
HDPrivateKey::HDPrivateKey(void){
    privateKey.compressed = true;
    memset(chainCode, 0, 32);
    depth = 0;
    memset(fingerprint, 0, 4);
    childNumber = 0;
}
HDPrivateKey::HDPrivateKey(const uint8_t secret[32],
                           const uint8_t chain_code[32],
                           uint8_t key_depth,
                           const uint8_t fingerprint_arr[4],
                           uint32_t child_number,
                           bool use_testnet){

    privateKey = PrivateKey(secret, true, use_testnet);
    memcpy(chainCode, chain_code, 32);
    depth = key_depth;
    childNumber = child_number;
    if(fingerprint_arr != NULL){
        memcpy(fingerprint, fingerprint_arr, 4);
    }else{
        memset(fingerprint, 0, 4);
    }
}
HDPrivateKey::HDPrivateKey(const char * xprvArr){
    size_t xprvLen = strlen(xprvArr);
    byte arr[85] = { 0 };
    size_t l = fromBase58Check(xprvArr, xprvLen, arr, sizeof(arr));
    if(l == 0){
        return; // decoding error
    }
    if( (memcmp(arr, XPRV_MAINNET_PREFIX, 4)!=0) && (memcmp(arr, XPRV_TESTNET_PREFIX, 4)!=0) ){
        // unknown format. TODO: implement yprv, zprv etc
        return;
    }
    bool testnet = false;
    if(memcmp(arr, XPRV_TESTNET_PREFIX, 4)==0){
        testnet = true;
    }
    depth = arr[4];
    memcpy(fingerprint, arr+5, 4);
    childNumber = 0;
    for(int i=0; i<4; i++){
        childNumber <<= 8;
        childNumber += arr[9+i];
    }
    memcpy(chainCode, arr+13, 32);
    uint8_t secret[32];
    memcpy(secret, arr+46, 32);
    privateKey = PrivateKey(secret, true, testnet);
}
HDPrivateKey::~HDPrivateKey(void) {
    // erase chain code from memory
    memset(chainCode, 0, 32);
    // privateKey will clean everything up by itself
}
int HDPrivateKey::fromSeed(const uint8_t seed[64], bool use_testnet){
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
int HDPrivateKey::fromMnemonic(const char * mnemonic, const char * password, bool use_testnet){
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
bool HDPrivateKey::isValid() const{
    return privateKey.isValid();
}
int HDPrivateKey::xprv(char * arr, size_t len) const{
    uint8_t hex[78] = { 0 };
    if(privateKey.testnet){
        memcpy(hex, XPRV_TESTNET_PREFIX, 4);
    }else{
        memcpy(hex, XPRV_MAINNET_PREFIX, 4);
    }
    hex[4] = depth;
    memcpy(hex+5, fingerprint, 4);
    for(uint8_t i=0; i<4; i++){
        hex[12-i] = ((childNumber >> (i*8)) & 0xFF);
    }
    memcpy(hex+13, chainCode, 32);
    memcpy(hex+46, privateKey.secret, 32);
    return toBase58Check(hex, sizeof(hex), arr, len);
}
String HDPrivateKey::xprv() const{
    char arr[112] = { 0 };
    xprv(arr, sizeof(arr));
    return String(arr);
}
size_t HDPrivateKey::printTo(Print &p) const{
    char arr[112] = { 0 };
    xprv(arr, sizeof(arr));
    return p.print(arr);
}
int HDPrivateKey::xpub(char * arr, size_t len) const{
    uint8_t hex[111] = { 0 }; // TODO: real length, in xpub compressed = true
    if(privateKey.testnet){
        memcpy(hex, XPUB_TESTNET_PREFIX, 4);
    }else{
        memcpy(hex, XPUB_MAINNET_PREFIX, 4);
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
    return toBase58Check(hex, 45+secLen, arr, len);
}
String HDPrivateKey::xpub() const{
    char arr[112] = { 0 };
    xpub(arr, sizeof(arr));
    return String(arr);
}
// TODO: refactor to single function!
HDPrivateKey HDPrivateKey::child(uint32_t index) const{
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
        // TODO: remove minusN, make (0xFF-N[i]) instead
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

HDPrivateKey HDPrivateKey::hardenedChild(uint32_t index) const{
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
        // TODO: remove minusN, make (0xFF-N[i]) instead
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

// ---------------------------------------------------------------- HDPublicKey class

HDPublicKey::HDPublicKey(void){
    publicKey.compressed = true;
    memset(chainCode, 0, 32);
    depth = 0;
    memset(fingerprint, 0, 4);
    childNumber = 0;
}
HDPublicKey::HDPublicKey(const uint8_t point[64],
                           const uint8_t chain_code[32],
                           uint8_t key_depth,
                           const uint8_t fingerprint_arr[4],
                           uint32_t child_number,
                           bool use_testnet){

    testnet = use_testnet;
    publicKey = PublicKey(point, true);
    memcpy(chainCode, chain_code, 32);
    depth = key_depth;
    childNumber = child_number;
    if(fingerprint_arr != NULL){
        memcpy(fingerprint, fingerprint_arr, 4);
    }else{
        memset(fingerprint, 0, 4);
    }
}
HDPublicKey::HDPublicKey(const char * xpubArr){
    size_t xpubLen = strlen(xpubArr);
    byte arr[85] = { 0 };
    size_t l = fromBase58Check(xpubArr, xpubLen, arr, sizeof(arr));
    if(l == 0){
        return; // decoding error
    }
    if( (memcmp(arr, XPUB_MAINNET_PREFIX, 4)!=0) && (memcmp(arr, XPUB_TESTNET_PREFIX, 4)!=0) ){
        // unknown format. TODO: implement ypub, zpub etc
        return;
    }
    testnet = false;
    if(memcmp(arr, XPUB_TESTNET_PREFIX, 4)==0){
        testnet = true;
    }
    depth = arr[4];
    memcpy(fingerprint, arr+5, 4);
    childNumber = 0;
    for(int i=0; i<4; i++){
        childNumber <<= 8;
        childNumber += arr[9+i];
    }
    memcpy(chainCode, arr+13, 32);
    byte sec_arr[33];
    memcpy(sec_arr, arr+45, 33);
    publicKey.fromSec(sec_arr);
}
HDPublicKey::~HDPublicKey(void) {
    // erase chain code from memory
    memset(chainCode, 0, 32);
}
bool HDPublicKey::isValid() const{
    return publicKey.isValid();
}
int HDPublicKey::xpub(char * arr, size_t len) const{
    uint8_t hex[111] = { 0 }; // TODO: real length, in xpub compressed = true
    if(testnet){
        memcpy(hex, XPUB_TESTNET_PREFIX, 4);
    }else{
        memcpy(hex, XPUB_MAINNET_PREFIX, 4);
    }
    hex[4] = depth;
    memcpy(hex+5, fingerprint, 4);
    for(uint8_t i=0; i<4; i++){
        hex[12-i] = ((childNumber >> (i*8)) & 0xFF);
    }
    memcpy(hex+13, chainCode, 32);

    uint8_t sec[65] = { 0 };
    int secLen = publicKey.sec(sec, sizeof(sec));
    memcpy(hex+45, sec, secLen);
    return toBase58Check(hex, 45+secLen, arr, len);
}
String HDPublicKey::xpub() const{
    char arr[114] = { 0 };
    xpub(arr, sizeof(arr));
    return String(arr);
}
size_t HDPublicKey::printTo(Print &p) const{
    char arr[114] = { 0 };
    xpub(arr, sizeof(arr));
    return p.print(arr);
}
HDPublicKey HDPublicKey::child(uint32_t index) const{
    HDPublicKey child;

    uint8_t sec[65] = { 0 };
    int l = publicKey.sec(sec, sizeof(sec));
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

    uint8_t secret[32];
    memcpy(secret, raw, 32);
    const struct uECC_Curve_t * curve = uECC_secp256k1();
    uint8_t p[64] = {0};
    uECC_compute_public_key(secret, p, curve);

    uint8_t point[64] = { 0 };
    uECC_add_points(p, publicKey.point, point, curve);

    child.publicKey = PublicKey(point, true);
    child.testnet = testnet;
    return child;
}