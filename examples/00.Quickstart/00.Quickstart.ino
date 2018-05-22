#include <Bitcoin.h>

void setup() {
  Serial.begin(9600);
  while(!Serial){
    ; // waiting for serial port to open
  }

  // Single private key for testnet
  PrivateKey privateKey("cQwxqQwCwGoirnTkVnNt4XqJuEv24HYBvVWCTLtL5g1kx9Q1AEhE");

  // Defining transaction that we will spend. txid and output number
  TransactionInput txIn("838395321d85119d0872efa1155bb764db24ee8231224576ef1929d8e63ae70e", 0);

  // Addresses to send bitcoins to
  // It can be either char array or String
  char destinationAddress[] = "mqSK6CUkT4b1YLpUSgA4rkB3YDr7eZKNXd";
  String changeAddress = privateKey.address();

  // Amounts to send
  // Unsigned long can store up to 4294967295 satoshi (42.9 BTC)
  // For larger amounts use uint64_t
  unsigned long availableAmount = 2000000; // 20 mBTC
  unsigned long fee = 1500;
  unsigned long sendAmount = 1000000; // 10 mBTC
  unsigned long changeAmount = availableAmount - sendAmount - fee;

  TransactionOutput txOutDestination(sendAmount, destinationAddress);
  TransactionOutput txOutChange(changeAmount, changeAddress);

  // Constructing actual transaction
  Transaction tx;
  tx.addInput(txIn);
  tx.addOutput(txOutDestination);
  tx.addOutput(txOutChange);
  
  // Signing transaction
  // Returns signature and populates transaction input's scriptSig
  Signature sig = tx.signInput(0, privateKey);

  // Printing transaction id
  Serial.println("Transaction id:");
  Serial.println(tx.id());  

  // Printing raw transaction
  Serial.println("Signed transaction:");
  Serial.println(tx);
}

void loop() {

}
