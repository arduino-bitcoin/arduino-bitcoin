#include <Bitcoin.h>

char mnemonic[] = "club bright surface match same attract fatigue horse issue lounge kick very";
char password[] = "password";
byte seed[] = { 0x9f, 0xcd, 0xb6, 0x2d, 0xf0, 0x13, 0x83, 0x5a, 
                0x03, 0x16, 0xfd, 0x2e, 0x20, 0xff, 0x56, 0x4a, 
                0x15, 0x81, 0xcc, 0xd6, 0xbb, 0x37, 0x9c, 0x99, 
                0x42, 0x0a, 0x1c, 0x64, 0x69, 0xcc, 0x40, 0xb3, 
                0xc0, 0xff, 0x42, 0xcf, 0x4d, 0xfa, 0x23, 0x0a, 
                0x25, 0xb7, 0x35, 0xee, 0x36, 0x5e, 0x55, 0x32, 
                0x47, 0x6d, 0xb3, 0x6d, 0x7f, 0xf4, 0xba, 0xa4, 
                0x62, 0x0f, 0x33, 0x95, 0x73, 0x6f, 0xa6, 0xc8 };

//char rawTx[] = "0100000001a7afb2df5a4c5df7821bdb84c1ec7c21f9f51b48b8d4756db93ba2939ae09c76000000005701ff4c53ff043587cf036215555e80000000b061c3d2745a648716425515c84c227608a9e37f9314fff1ae1333a3d103e9ad02e2060e384cdd7431b92080514b9bb7df44a034873f0453124b6bd35945d013c000000000fdffffff0240420f00000000001976a914767febc7c1c2b7d641aeb64cf0e791cbe9d7e2b588ac5e538900000000001976a91425032d3a2626a22099e29358d7d073075d800ac488ac18bd1300";
//char rawTx[] = "0100000002b13302576438b3ab2b74520b2ea16aad4e63dea0ea8e8f5b55fb1bf2fceffb38010000005701ff4c53ff043587cf036215555e80000000b061c3d2745a648716425515c84c227608a9e37f9314fff1ae1333a3d103e9ad02e2060e384cdd7431b92080514b9bb7df44a034873f0453124b6bd35945d013c001000000fdffffff5c512f41c41cfee59f803f56855a50eb00570f00c7984b427954742e24da7bd9000000005701ff4c53ff043587cf036215555e80000000b061c3d2745a648716425515c84c227608a9e37f9314fff1ae1333a3d103e9ad02e2060e384cdd7431b92080514b9bb7df44a034873f0453124b6bd35945d013c000000100fdffffff02a8063d00000000001976a9147e3e9ede2ebd185d77ba7c44b1954d836a3ab11b88ac80969800000000001976a91465cf06e7f042738179e9a57b6271988752e21c0288ac8ebd1300";
//char hex[] = "0100000001affce06332365907dba9d38fca0f1a8fe84ac6003de2576441651c831fa0bfb1000000005701ff4c53ff043587cf036215555e80000000b061c3d2745a648716425515c84c227608a9e37f9314fff1ae1333a3d103e9ad02e2060e384cdd7431b92080514b9bb7df44a034873f0453124b6bd35945d013c001000100fdffffff0240420f00000000001976a914611aec9ad22029489eeac063538ccd24fc0b953188ac86c32d00000000001976a9141f389025d01ee8f83a3b82f39cbe4adbf27864f588acc3bd1300";
char hex[] = "010000000167881a297b7f3170263bc386663295b57ecebb24bdd5a9fc2a3d2aa7bb13bc68010000006a47304402200a533e645d63ba98ad4b7edaea7bef7b11e62c8e3d8fbc8895e114b2a5f4a69002205bdf1e9c48e3de308e9bb33e2ba4f8d84838d4c70d5bebc8adaa797f62baa7a2012102735954707bb655bad2962c096347202a7ee635480d03c63786763a503ce91954fdffffff02404b4c00000000001976a914b128c52884a6f43208b0af6d079586d8ddeed77c88ac90199505000000001976a9142bc5f58bef017525a6c670a8d7b4041799f8189088ac06ae1300";
byte raw[225];

void setup() {
  Serial.begin(9600);
  while(!Serial){
    ;
  }

  size_t len = fromHex(hex, raw, sizeof(raw));
  Serial.println(toHex(raw, sizeof(raw)));
  Serial.print("Raw length: ");
  Serial.println(len);
  
  Transaction tx;
  size_t cur = tx.parse(raw, len);
  Serial.print("Tx length: ");
  Serial.println(cur);

  Serial.print("Version: ");
  Serial.println(tx.version);
  Serial.print("Inputs:  ");
  Serial.println(tx.inputsNumber);
  for(int i=0; i< tx.inputsNumber; i++){
    Serial.print("\tHash:          ");
    Serial.println(toHex(tx.txIns[i].hash, 32));
    Serial.print("\tOutput index:  ");
    Serial.println(tx.txIns[i].outputIndex);
    Serial.print("\tScript length: ");
    Serial.println(tx.txIns[i].scriptSig.length());
    Serial.print("\tScript:        ");
    Serial.println(tx.txIns[i].scriptSig);
    Serial.print("\tSequence:      ");
    Serial.println(tx.txIns[i].sequence);
  }
  Serial.print("Outputs: ");
  Serial.println(tx.outputsNumber);

  for(int i=0; i< tx.outputsNumber; i++){
    Serial.print(tx.txOuts[i].address(true));
    Serial.print(": ");
    Serial.print(((float)tx.txOuts[i].amount)/100000);
    Serial.println(" mBTC");
  }

  Serial.print("Tx length(): ");
  Serial.println(tx.length());
  byte ser[255];
  size_t l = tx.serialize(ser, sizeof(ser));
  Serial.println(toHex(ser, l));

//  HDPrivateKey hdKey;
//  hdKey.fromSeed(seed, true);
//  HDPrivateKey accountKey = hdKey.hardenedChild(44).hardenedChild(1).hardenedChild(0);
  
//  Serial.println(tx.sign(accountKey));
  Serial.println("Done!");
}

void loop() {
  // put your main code here, to run repeatedly:

}
