# did:key resolver

[![npm version](https://badge.fury.io/js/%40sondreb%2Fdid-key.svg)](https://www.npmjs.com/package/@sondreb/did-key)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A JavaScript library implementing the "did:key" Decentralized Identifier (DID) method, supports ed25519 and secp256k1 for DID creation and resolution.

The library was built to have a web friendly package that works without relying on `Buffer` and `crypto` from Node.js.

## Installation

```bash
npm install @sondreb/did-key
```

## Examples

```js
import { DidKey } from '@sondreb/did-key';

const ed25519Key = DidKey.generate('ed25519');
const secp256k1Key = DidKey.generate('secp256k1');

const didResolution = DidKey.resolve(ed25519Key.did);

const document1 = DidKey.fromPrivateKey(privateKey, 'secp256k1');
const document2 = DidKey.fromPrivateKey(privateKey, 'ed25519');
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.