#include <Bitcoin.h>
#include <OpCodes.h>


void setup() {
  Serial.begin(9600);
  while(!Serial){
    ;
  }
  PublicKey pubkey("027db253fdbd66a4efa20051e7d03294ac6b7c97ce9fa3caaeae96fd4c283ffb15");
  Serial.println(pubkey);
  Serial.println(pubkey.address());
  Serial.println(pubkey.script());
}

void loop() {
  // put your main code here, to run repeatedly:

}
