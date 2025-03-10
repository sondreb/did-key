import { TestRunner } from './test-utils.js';
import { DidKey } from '../lib/index.js';

// Helper for DidKey tests
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

// Mock ed25519 for testing
// const ed25519 = {
//   getPublicKey: (privateKey) => {
//     // Just a mock implementation for testing
//     return new Uint8Array(32).fill(3);
//   }
// };

// Add these to global scope for DidKey to use
globalThis.bytesToHex = bytesToHex;
// globalThis.ed25519 = ed25519;

export function runDidKeyTests() {
  const runner = new TestRunner();
  console.log('\n🧪 Running DidKey Tests...');

  runner.test('DidKey.generate', () => {
    const ed25519Key = DidKey.generate('ed25519');
    const secp256k1Key = DidKey.generate('secp256k1');

    runner.assertTrue(ed25519Key.did.startsWith('did:key:z6Mk'));
    runner.assertTrue(secp256k1Key.did.startsWith('did:key:zQ3s'));
  });

  runner.test('DidKey.resolve', () => {
    const ed25519Key = DidKey.generate('ed25519');
    const didResolution = DidKey.resolve(ed25519Key.did);
    runner.assertEquals(didResolution.didDocument.id, ed25519Key.did);
  });

  runner.test('DidKey.fromPrivateKey (secp256k1)', () => {

    const privateKey = new Uint8Array([
      26, 113, 186, 116, 181,  43, 242, 116,
      84, 207, 225, 229,  23, 118, 199,  74,
     154,  39, 167,  26, 231,  17, 245,  91,
     138,  72, 109, 212, 159, 105,  46, 214
   ]);

   const document = DidKey.fromPrivateKey(privateKey, 'secp256k1');
    const did = `did:key:zQ3shrrqApMHnwgHBagm6XuVpGGuAM7RbRXbf57pmvTLUnQUt`;

    runner.assertEquals(document.verificationMethod[0].publicKeyMultibase, 'zQ3shrrqApMHnwgHBagm6XuVpGGuAM7RbRXbf57pmvTLUnQUt', 'Verification method should contain public key');
    runner.assertEquals(document.id, did, 'DID document should contain the DID');
});

runner.test('DidKey.fromPrivateKey (ed25519)', () => {

  const privateKey = new Uint8Array([
    56, 208,   7,  98,  73, 230, 151, 127,
   112,  75, 205, 183, 110, 163,  37, 147,
   113,   1,  24,  94, 176, 137,  38, 190,
   201, 106, 114,  15, 209, 240,  58, 129
 ]);

 const document = DidKey.fromPrivateKey(privateKey, 'ed25519');
  const did = `did:key:z6MkqKr4zKAKnDP1tWGDayDYe4YkrgUwVwMYSpqoesQ5STKq`;

  runner.assertEquals(document.verificationMethod[0].publicKeyMultibase, 'z6MkqKr4zKAKnDP1tWGDayDYe4YkrgUwVwMYSpqoesQ5STKq', 'Verification method should contain public key');
  runner.assertEquals(document.id, did, 'DID document should contain the DID');
});


  return runner.summarize();
}
