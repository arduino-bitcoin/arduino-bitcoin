#include <Bitcoin.h>

void setup() {
  Serial.begin(9600);
  while(!Serial){
    ;
  }

  // Single private key for testnet
  PrivateKey privateKey("cQwxqQwCwGoirnTkVnNt4XqJuEv24HYBvVWCTLtL5g1kx9Q1AEhE");

  TransactionInput txIn("c497cec7ca71466478833d27177299d01a72cb1db92278c68e2c5ee1a7560121", 1);

  // addresses to send bitcoins
  char destinationAddress[] = "mqqXkvzA5y1MgvWTaHWXFgJCWDA959cN1K";
  char changeAddress[36] = { 0 };
  privateKey.address(changeAddress, 35);

  // amounts to send
  // unsigned long can store up to 4294967295 satoshi (42.9 BTC)
  // for larger amounts use uint64_t
  unsigned long availableAmount = 5800000; // 58 mBTC
  unsigned long sendAmount = 2000000; // 20 mBTC
  unsigned long fee = 1500;
  unsigned long changeAmount = availableAmount - sendAmount - fee;

  TransactionOutput txOutDestination(sendAmount, destinationAddress);
  TransactionOutput txOutChange(changeAmount, changeAddress);

  // constructing actual transaction
  Transaction tx;
  tx.addInput(txIn);
  tx.addOutput(txOutDestination);
  tx.addOutput(txOutChange);
  
  // Printing transaction information
  Serial.print("Tx length: ");
  Serial.println(tx.length());

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
  Serial.println("Unsigned transaction:");
  Serial.println(toHex(ser, l));

  // signing transaction
  Serial.println("Signing transaction...");
  Signature sig = tx.signInput(0, privateKey);
  Serial.println(sig);

  Serial.print("Signed tx length(): ");
  Serial.println(tx.length());
  l = tx.serialize(ser, sizeof(ser));
  Serial.println("Signed transaction:");
  Serial.println(toHex(ser, l));

  uint8_t id_arr[32];
  tx.id(id_arr);
  Serial.println("Transaction id:");
  Serial.println(toHex(id_arr,32));
  
  Serial.println("Done");
}

void loop() {
  // put your main code here, to run repeatedly:

}
