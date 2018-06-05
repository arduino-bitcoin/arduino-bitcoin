#include <Bitcoin.h>

void testDerParsing(char * hex){
  Serial.print("\t");
  Serial.println(hex);
  byte arr[72];
  size_t l = fromHex(hex, arr, sizeof(arr));
  Signature sig(hex);
  if(sig){
    Serial.print("\t");
    Serial.println(sig);
    Serial.println("Valid signature");
    byte arr2[72];
    size_t l2 = sig.der(arr2, sizeof(arr2));
    if(memcmp(arr, arr2, l)==0 && l==l2){
      Serial.println("Signatures are the same");
    }else{
      Serial.println("Not OK! Signatures are different");
    }
  }else{
    Serial.println("Invalid signature");
  }
}

void testConstructor(char * hex){
  Serial.println(hex);
  Signature sig(hex);
  Serial.println(sig);
  if(sig){
    Serial.println("Valid signature");
  }else{
    Serial.println("Invalid signature");
  }
  String str = hex;
  Signature sig2(str);
  Serial.println(sig2);
  if(sig2){
    Serial.println("Valid signature");
  }else{
    Serial.println("Invalid signature");
  }
}

void setup() {
  Serial.begin(9600);
  while(!Serial){
    ; // wait for serial port
  }
  Signature sig;
  if(!sig){
    Serial.println("OK. Invalid signature");
  }else{
    Serial.println("Not OK! Should be invalid");
  }
  
  Serial.println("\nValid signature encodings");
  testDerParsing("3044022065017359a1e5d8035c3bd1bf84a237145cdb1f9f80c671fa3153a818805dab1f02205564b587296bac49aa1f47f108aa3c387e8fd90bdd7b93bc33c7ae05d042f7d6");
  testDerParsing("3045022100839301f94c03e7c6909b0b08f568cb9032ba6c2e4577f5e55c6b71d606129b2e02206a47cbfe20ab252496a9dbdf6695387d7bca78e879a4c689dd0339b01f68a9cd");
  testDerParsing("300d020449df86c1020501100cfb0d");
  testDerParsing("301002060092393857930206009564253453");

  Serial.println("\nInvalid signature encodings");
  testDerParsing("304502210065017359a1e5d8035c3bd1bf84a237145cdb1f9f80c671fa3153a818805dab1f02205564b587296bac49aa1f47f108aa3c387e8fd90bdd7b93bc33c7ae05d042f7d6");
  testDerParsing("30440220839301f94c03e7c6909b0b08f568cb9032ba6c2e4577f5e55c6b71d606129b2e02206a47cbfe20ab252496a9dbdf6695387d7bca78e879a4c689dd0339b01f68a9cd");
  testDerParsing("300e02050049df86c1020501100cfb0d");
  testDerParsing("300f020592393857930206009564253453");

  Serial.println("\nConstructors test");
  testConstructor("300d020449df86c1020501100cfb0d");
  testConstructor(" ;;300d020449df86c1020501100cfb0d]]");  // should skip leading non-hex characters and not reach final ones
  testConstructor("300d020449df86-c1020501100cfb0d"); // should fail as "-" is in the middle
  testConstructor("300d020449df86c1020501100cfb0dfee"); // should not reach last two characters
}

void loop() {
  // put your main code here, to run repeatedly:

}
