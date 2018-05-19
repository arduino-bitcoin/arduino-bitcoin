#include <Bitcoin.h>

// TODO: refactor

// legacy transaction
//char hex[] = "010000000167881a297b7f3170263bc386663295b57ecebb24bdd5a9fc2a3d2aa7bb13bc68010000006a47304402200a533e645d63ba98ad4b7edaea7bef7b11e62c8e3d8fbc8895e114b2a5f4a69002205bdf1e9c48e3de308e9bb33e2ba4f8d84838d4c70d5bebc8adaa797f62baa7a2012102735954707bb655bad2962c096347202a7ee635480d03c63786763a503ce91954fdffffff02404b4c00000000001976a914b128c52884a6f43208b0af6d079586d8ddeed77c88ac90199505000000001976a9142bc5f58bef017525a6c670a8d7b4041799f8189088ac06ae1300";
// segwit transaction
char hex[] = "0100000000010195ffbcc7e87799f6c5bbb117130a0d7734088368034e489c7619992578e7aea90000000000fdffffff0172ef390000000000160014c52f6d0a3ebf2ee79ca392053d5f272ebc9d78f902483045022100b98d55c7cdd394d609a139b913efdbd552a1f136e826082732a6d54526ca0a71022070ee9cd6c082bab31a5a320a5e9d8e4a4b06e9c3f7f0c4990649634ed6f8a312012103ff8c3029835ddde33484aabbe19e7423227d31c6100ef9d7c137230e13b02b28b2ce1300";
byte raw[225];

void setup() {
  Serial.begin(9600);
  while(!Serial){
    ;
  }

  size_t len = fromHex(hex, raw, sizeof(raw));
  Serial.println(toHex(raw, len));
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
    if(tx.txIns[i].isSegwit()){
      Serial.print("\tWitness program:");
      Serial.println(tx.txIns[i].witnessProgram);
    }
  }
  Serial.print("Outputs: ");
  Serial.println(tx.outputsNumber);

  for(int i=0; i< tx.outputsNumber; i++){
    Serial.print("\t");
    Serial.print(tx.txOuts[i].address(true));
    Serial.print(": ");
    Serial.print(((float)tx.txOuts[i].amount)/100000);
    Serial.println(" mBTC");
  }

  Serial.println(tx);
//  Serial.print("Tx length(): ");
//  Serial.println(tx.length());
//  byte ser[255];
//  size_t l = tx.serialize(ser, sizeof(ser));
//  Serial.println(toHex(ser, l));

  byte h[32];
  tx.hash(h);
  Serial.print("Hash: ");
  Serial.println(toHex(h, sizeof(h)));

  byte arr2[] = { 0x76, 0xa9, 0x14, 0xb1, 0x28, 0xc5, 0x28, 0x84, 0xa6, 0xf4, 
                  0x32, 0x08, 0xb0, 0xaf, 0x6d, 0x07, 0x95, 0x86, 0xd8, 0xdd, 
                  0xee, 0xd7, 0x7c, 0x88, 0xac };
  Script pscript(arr2, sizeof(arr2));
  Serial.println(pscript);
  tx.sigHash(0, pscript, h);
  Serial.print("SigHash: ");
  Serial.println(toHex(h, sizeof(h)));

  Serial.println("Done!");
}

void loop() {
  // put your main code here, to run repeatedly:

}
