#include <Bitcoin.h>
#define VERBOSE false

void testDerParsing(char * hex, bool valid){
  if(VERBOSE){
    Serial.print("\t");
    Serial.println(hex);
  }
  byte arr[72];
  size_t l = fromHex(hex, arr, sizeof(arr));
  Signature sig(hex);
  if(sig){
    if(VERBOSE){
      Serial.print("\t");
      Serial.println(sig);
      Serial.println("Valid signature");
    }
    byte arr2[72];
    size_t l2 = sig.der(arr2, sizeof(arr2));
    if(memcmp(arr, arr2, l)==0 && l==l2){
      Serial.println("OK, signatures are the same");
    }else{
      Serial.println("ERROR! Signatures are different");
    }
  }else{
    if(VERBOSE){
      Serial.println("Invalid signature");
    }
  }
  if(bool(sig) == valid){
    Serial.println("OK. Test passed");
  }else{
    Serial.println("ERROR. Test failed");
  }
}

void testConstructors(char * hex, bool valid){
  Signature sig(hex);
  if(VERBOSE){
    Serial.println(hex);
    Serial.println(sig);
    if(sig){
      Serial.println("Valid signature");
    }else{
      Serial.println("Invalid signature");
    }
  }
  String str = hex;
  Signature sig2(str);
  if(VERBOSE){
    Serial.println(sig2);
    if(sig2){
      Serial.println("Valid signature");
    }else{
      Serial.println("Invalid signature");
    }
  }
  if(bool(sig) == valid && sig==sig2){
    Serial.println("OK. Test passed");
  }else{
    Serial.println("ERROR. Test failed");
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
  testDerParsing("3044022065017359a1e5d8035c3bd1bf84a237145cdb1f9f80c671fa3153a818805dab1f02205564b587296bac49aa1f47f108aa3c387e8fd90bdd7b93bc33c7ae05d042f7d6", true);
  testDerParsing("3045022100839301f94c03e7c6909b0b08f568cb9032ba6c2e4577f5e55c6b71d606129b2e02206a47cbfe20ab252496a9dbdf6695387d7bca78e879a4c689dd0339b01f68a9cd", true);
  testDerParsing("300d020449df86c1020501100cfb0d", true);
  testDerParsing("301002060092393857930206009564253453", true);

  Serial.println("\nInvalid signature encodings");
  testDerParsing("304502210065017359a1e5d8035c3bd1bf84a237145cdb1f9f80c671fa3153a818805dab1f02205564b587296bac49aa1f47f108aa3c387e8fd90bdd7b93bc33c7ae05d042f7d6", false);
  testDerParsing("30440220839301f94c03e7c6909b0b08f568cb9032ba6c2e4577f5e55c6b71d606129b2e02206a47cbfe20ab252496a9dbdf6695387d7bca78e879a4c689dd0339b01f68a9cd", false);
  testDerParsing("300e02050049df86c1020501100cfb0d", false);
  testDerParsing("300f020592393857930206009564253453", false);

  Serial.println("\nConstructors test");
  testConstructors("300d020449df86c1020501100cfb0d", true);
  testConstructors(" ;;300d020449df86c1020501100cfb0d]]", true);  
  testConstructors("300d020449df86-c1020501100cfb0d", false);
  testConstructors("300d020449df86c1020501100cfb0dfee", true);
}

void loop() {
  // put your main code here, to run repeatedly:

}
