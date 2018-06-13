#include <Bitcoin.h>
#define VERBOSE false

//void testType(char * hex, int type){
//  byte buf[255];
//  size_t len = fromHex(hex, buf, sizeof(buf));
//  Script script(buf, len);
//  if(VERBOSE){
//    Serial.println(hex);
//    Serial.println(script);
//    Serial.print("Type: ");
//    Serial.println(script.type());
//  }
//  if(script.type() == type){
//    Serial.println("OK. Test passed");
//  }else{
//    Serial.println("ERROR. Test failed");
//  }
//}
//
//void testAddress(char * hex, bool testnet, String addr){
//  byte buf[255];
//  size_t len = fromHex(hex, buf, sizeof(buf));
//  Script script(buf, len);
//  Script script2(addr);
//  if(VERBOSE){
//    Serial.println(hex);
//    Serial.println(script2);
//    Serial.println(addr);
//    Serial.println(script.address(testnet));
//  }
//  if((script.address(testnet) == addr) && (script == script2)){
//    Serial.println("OK. Test passed");
//  }else{
//    Serial.println("ERROR. Test failed");
//  }
//}

void setup() {
  Serial.begin(9600);
  while(!Serial){
    ; // wait for serial port
  }
  char secCompressed[] = "039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5";
  char secUncompressed[] = "049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9";
  PublicKey pubkey(secCompressed);
  Serial.println(secCompressed);
  Serial.println(pubkey);
  pubkey.compress();
  PublicKey pubkey2(secUncompressed);
  Serial.println(secUncompressed);
  Serial.println(pubkey);
  if(pubkey == pubkey2){
    Serial.println("OK, keys are the same");
  }else{
    Serial.println("ERROR: keys are different");
  }
}

void loop() {
  // put your main code here, to run repeatedly:

}
