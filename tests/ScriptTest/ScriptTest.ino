#include <Bitcoin.h>
#include <OpCodes.h>
#define VERBOSE true

void testType(char * hex, int type){
  byte buf[255];
  size_t len = fromHex(hex, buf, sizeof(buf));
  Script script(buf, len);
  if(VERBOSE){
    Serial.println(hex);
    Serial.println(script);
    Serial.print("Type: ");
    Serial.println(script.type());
  }
  if(script.type() == type){
    Serial.println("OK. Test passed");
  }else{
    Serial.println("ERROR. Test failed");
  }
}

void testAddress(char * hex, bool testnet, String addr){
  byte buf[255];
  size_t len = fromHex(hex, buf, sizeof(buf));
  Script script(buf, len);
  Script script2(addr);
  if(VERBOSE){
    Serial.println(hex);
    Serial.println(script2);
    Serial.println(addr);
    Serial.println(script.address(testnet));
  }
  if((script.address(testnet) == addr) && (script == script2)){
    Serial.println("OK. Test passed");
  }else{
    Serial.println("ERROR. Test failed");
  }
}

void testPush(){
  Script script;
  script.push(OP_DUP);
  script.push(OP_HASH160);
  byte h160[20] = { 0 };
  fromHex("21df06f1b8f6b989469b6da0209527857794d736", h160, sizeof(h160));
  script.push(sizeof(h160)); // length
  script.push(h160, sizeof(h160));
  script.push(OP_EQUALVERIFY);
  script.push(OP_CHECKSIG);
  Serial.println(script);
  // TODO: check automatically
  Serial.println("Done");
}

void setup() {
  Serial.begin(9600);
  while(!Serial){
    ; // wait for serial port
  }
  Script script;
  if(!script){
    Serial.println("OK. Script is empty");
  }else{
    Serial.println("Not OK! Should be empty");
  }

  Serial.println("Script type test:");
  testType("76a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac", P2PKH);
  testType("a91474d691da1574e6b3c192ecfb52cc8984ee7b6c5687", P2SH);
  testType("0014751e76e8199196d454941c45d1b3a323f1433bd6", P2WPKH);
  testType("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", P2WSH);

  Serial.println("Script address test:");
  testAddress("76a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac", false, "15hZo812Lx266Dot6T52krxpnhrNiaqHya");
  testAddress("76a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac", true, "mkDX6B619yTLsLHVp23QanB9ehT5bcf89D");
  testAddress("a91474d691da1574e6b3c192ecfb52cc8984ee7b6c5687", false, "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh");
  testAddress("a91474d691da1574e6b3c192ecfb52cc8984ee7b6c5687", true, "2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B");
  testAddress("0014751e76e8199196d454941c45d1b3a323f1433bd6", false, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  testAddress("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", false, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");

  Serial.println("Script push test:");
  testPush();
}

void loop() {
  // put your main code here, to run repeatedly:

}
