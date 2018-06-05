# Documentation for Arduino Bitcoin library

> Documentation is not complete yet. Working on it...

## Getting started

### Installation

Bitcoin library can be installed as any other [Arduino library](https://www.arduino.cc/en/Guide/Libraries). Currently it is not available via Arduino Library Manager, as it is still in active development stage. To install it clone [repository](https://github.com/arduino-bitcoin/arduino-bitcoin) or [download](https://github.com/arduino-bitcoin/arduino-bitcoin/archive/master.zip) zip file. Copy `arduino-bitcoin` folder to you `Libraries` folder or install it with Arduino IDE using `Sketch > Include Library > Add .ZIP Library` menu.

After installation you will see a collection of examples under `File > Examples > Bitcoin` menu. You can start by looking at the examples or read our [tutorials](#tutorials-and-examples) and [library reference](#library-reference).

> Note: This library currently supports only 32-bit microcontrollers like Arduino Zero, Adafruit Feather M0 and similar. It was tested only on Adafruit Feather M0, but should also work on other 32-bit microcontrollers.

### Quickstart

In this section we will construct a [transaction on the testnet](https://testnet.blockchain.info/tx/15f5023a13779fcc2ca48ea538262fb9fcc2b4a74d2182c9712ad41a2cf18f50) sending 10 mBTC to address `mqSK6CUkT4b1YLpUSgA4rkB3YDr7eZKNXd`, sign it with private key and print signed raw transaction to the serial port.

We spend first output of the transaction with id [838395321d85119d0872efa1155bb764db24ee8231224576ef1929d8e63ae70e](https://testnet.blockchain.info/tx/838395321d85119d0872efa1155bb764db24ee8231224576ef1929d8e63ae70e).

Outputs of the transaction are:

- `10 mBTC` to `mqSK6CUkT4b1YLpUSgA4rkB3YDr7eZKNXd`
- `9.985 mBTC` back to the same address

Fee is `1500` satoshi.

```cpp
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
``` 

The only thing left is to copy signed raw transaction from serial monitor and broadcast it to the network. It can be done via Bitcoin Core full client, electrum console or on one of multiple web-based block explorers, for example [blockcypher](https://live.blockcypher.com/btc-testnet/pushtx/).

## Tutorials and examples

Examples:

- [Quickstart](../examples/00.Quickstart/00.Quickstart.ino)
- [PrivateKey usage](../examples/01.PrivateKey/01.PrivateKey.ino)
- [Addresses](../examples/02.Addresses/02.Addresses.ino)
- [Signature](../examples/03.Signature/03.Signature.ino)
- [Transaction construction](../examples/04.Transaction/04.Transaction.ino)
- [Transaction parsing](../examples/05.TransactionParse/05.TransactionParse.ino)
- [Mnemonic and HD wallet](../examples/06.Mnemonic/06.Mnemonic.ino)
- [Script](../examples/07.Script/07.Script.ino)
- [Multisig transaction](../examples/08.Multisig/08.Multisig.ino)
- [Segwit transaction](../examples/09.SegwitTransaction/09.SegwitTransaction.ino)
- [Nested segwit transaction](../examples/10.NestedSegwitTransaction/10.NestedSegwitTransaction.ino)

TODO: add tutorials

## Library reference

Arduino Bitcoin library is object-oriented. Most of the things are classes. For every class there is a page with general description, links to protocol documentation and a list of available methods.

### Keys

- [PrivateKey](PrivateKey/readme.md)
- PublicKey
- HDPrivateKey
- HDPublicKey

### Transactions

- Transaction
- TransactionInput
- TransactionOutput

### Other classes

- [Signature](Signature/readme.md)
- [Script](Script/readme.md)
- Block (not implemented yet)

### Helper functions

#### Hashing

- rmd160()
- sha256()
- hash160()
- doubleSha()
- sha512()
- sha512Hmac()

#### Conversion

- toHex()
- fromHex()
- ByteStream class