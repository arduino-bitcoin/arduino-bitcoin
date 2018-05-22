# Bitcoin library for Arduino (Work in progress)

Arduino library to work with Bitcoin private and public keys, HD wallets, transactions, scripts and everything else necessary to make your own DIY hardware wallet or any other bitcoin-powered hardware device.

**WORK IN PROGRESS**. Documentation is on the way.

**DON'T USE IT IN PRODUCTION AND ON REAL FUNDS**

This library is currently in alpha. It is already usable and have most of features to get started, but API is not final and probably will change over time.

We will appreciate your help in making this library better, issues and pull requests are very welcome!

## Documentation

Currently we are working on documentation. [Installation instructions](docs/#installation) and [quickstart guide](docs/#quickstart) are available in the [docs folder](docs/). Library reference is on the way.

There is also a collection of [examples](examples/) that can help you to get started.

## Features

List of currently implemented features:

- [HD wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [Mnemonic codes](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [Multi-signature](https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki)
- [Native Segwit and Segwit nested in Pay-To-Script-Hash](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
- [Bech32 addresses](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)