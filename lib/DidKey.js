import * as multibase from 'multibase';
import * as ed25519 from '@noble/ed25519';
import * as secp256k1 from '@noble/secp256k1';
import { sha512 } from '@noble/hashes/sha512';

ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

export class DidKey {
    // Add multicodec constants
    static MULTICODEC = {
        ED25519_PUB: 0xed,
        SECP256K1_PUB: 0xe7
    };

    static publicKeyToMultibase(publicKeyBytes, keyType) {
        // Validate key type and length
        let multicodecValue;
        let expectedLength;
        
        switch(keyType) {
            case 'ed25519':
                multicodecValue = this.MULTICODEC.ED25519_PUB;
                expectedLength = 32;
                break;
            case 'secp256k1':
                multicodecValue = this.MULTICODEC.SECP256K1_PUB;
                expectedLength = 33;
                break;
            default:
                throw new Error(`Unsupported key type: ${keyType}`);
        }

        if (publicKeyBytes.length !== expectedLength) {
            throw new Error(`Invalid key length for ${keyType}. Expected ${expectedLength} bytes, got ${publicKeyBytes.length}`);
        }

        // Create varint bytes for the multicodec
        const varintBytes = new Uint8Array([multicodecValue]);
        
        // Combine multicodec prefix with public key bytes
        const prefixedKey = new Uint8Array([...varintBytes, 0x01, ...publicKeyBytes]);
        
        // Encode using base58btc multibase encoding with 'z' prefix
        return new TextDecoder().decode(multibase.encode('base58btc', prefixedKey));
    }

    static resolve(did) {
      const didDocument = DidKey.getDocument(did);

      return {
        didResolutionMetadata: { 
          contentType: 'application/did+ld+json',
          retrieved: new Date().toISOString(),
         },
        didDocument: didDocument,
        didDocumentMetadata: {  }
      }
    }

    static generate(keyType) {
      let privKey = undefined;
      let pubKey = undefined;

      if (keyType === 'secp256k1') {
        privKey = secp256k1.utils.randomPrivateKey();
        pubKey = secp256k1.getPublicKey(privKey);
      }

      if (keyType === 'ed25519') {
        privKey = ed25519.utils.randomPrivateKey();
        pubKey = ed25519.getPublicKey(privKey);
      }

      return {
        privateKey: privKey,
        publicKey: pubKey,
        did: 'did:key:' + DidKey.publicKeyToMultibase(pubKey, keyType)
      };
    }

    static fromPublicKey(publicKey, keyType) {
      const identifier = `did:key:${DidKey.publicKeyToMultibase(publicKey, keyType)}`;
      return DidKey.getDocument(identifier);
    }

    static fromPrivateKey(privateKey, keyType) {
      let publicKey = undefined;
      if (keyType === 'secp256k1') {
        publicKey = secp256k1.getPublicKey(privateKey);
      }

      if (keyType === 'ed25519') {
        publicKey = ed25519.getPublicKey(privateKey);
      }

      const identifier = `did:key:${DidKey.publicKeyToMultibase(publicKey, keyType)}`;
      return DidKey.getDocument(identifier);
    }

    // static getPublicKey(privateKeyText) {
    //     const privateKeyData = StrKey.decodeEd25519SecretSeed(privateKeyText);
    //     // const privateKeyHex = bytesToHex(privateKeyData);
    //     const publicKeyData = ed25519.getPublicKey(privateKeyData);
    //     // const publicKeyData = ed25519.getPublicKey(privateKeyHex);
    //     const publicKeyString = StrKey.encodeEd25519PublicKey(publicKeyData);
    //     return publicKeyString;
    // }

    static getDocument(did) {
        const keyUri = `${did}#0`;
        const publicKeyText = did.split(':')[2];
        
        // Determine key type from DID string
        const keyType = publicKeyText.startsWith('zQ3s') ? 'secp256k1' : 
                       publicKeyText.startsWith('z6Mk') ? 'ed25519' : 
                       undefined;

        if (!keyType) {
            throw new Error('Unsupported key type in DID');
        }

        // const publicKeyData = StrKey.decodeEd25519PublicKey(publicKeyText);
        // const multibaseKey = DidKey.publicKeyToMultibase(publicKeyData, keyType);
        const multibaseKey = publicKeyText;

        const type = keyType === 'ed25519' ? 'Ed25519VerificationKey2020' : 'EcdsaSecp256k1VerificationKey2019';

        let  document = `{
            "@context": [
              "https://www.w3.org/ns/did/v1"
            ],
            "id": "${did}",
            "verificationMethod": [
              {
                "id": "${keyUri}",
                "type": "${type}",
                "controller": "${did}",
                "publicKeyMultibase": "${multibaseKey}"
              }
            ],
            "authentication": [
              "${keyUri}"
            ],
            "assertionMethod": [
              "${keyUri}"
            ],
            "capabilityDelegation": [
              "${keyUri}"
            ],
            "capabilityInvocation": [
              "${keyUri}"
            ]
          }`;

          return JSON.parse(document);
    }
}