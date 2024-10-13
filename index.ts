import { DeviceType, KeyPairType, PreKeyPairType, SessionBuilder, SessionCipher, SignalProtocolAddress, SignedPreKeyPairType } from './src'
import { SignalProtocolStore } from './src/__test__/storage-type'
import { binaryStringToArrayBuffer, uint8ArrayToArrayBuffer } from './src/helpers'

const ALICE_ADDRESS = new SignalProtocolAddress('+14151111111', 1)
const BOB_ADDRESS = new SignalProtocolAddress('+14152222222', 1)

const aliceStore = new SignalProtocolStore()
const bobStore = new SignalProtocolStore();

(async () => {
  aliceStore.put('registrationId', 1001)
  aliceStore.put('identityKey', {
    pubKey: hexToArrayBuffer("054ee36a5fd60cffac11e4deb45d16a087b3473065fffaf20602b1dec76a715c50"),
    privKey: hexToArrayBuffer("4870ef96dcc0541144d0a76242b4a1870ffd260956ac623fcafa5053934fe752"),
  })

  const bobIdentityKey: KeyPairType = {
    pubKey: hexToArrayBuffer("05b27ac1a76e5f691bca7212a7beb19d296b2ab3820fc9d95eed73e93eb0bec56f"),
    privKey: hexToArrayBuffer("388db1cf370d258717d2e2f66656417d4931936e042a2e86f594ca0619ad0370"),
  }

  const bobPreKey: PreKeyPairType = {
    keyId: 2001,
    keyPair: {
      pubKey: hexToArrayBuffer("05df8d7e5fcc0b1fa5b662869df83cca9fbcf8ae145e9b26f563ffde9394c0e32a"),
      privKey: hexToArrayBuffer("a062bf1075c28ebd91fe723bccc9553f96108221571e8829274699d1d2f32554"),
    }
  }

  const bobSignedPreKey: SignedPreKeyPairType = {
    keyId: 3001,
    keyPair: {
      pubKey: hexToArrayBuffer("058828328e7048879c181719373dc1bf6ac9e55ac337c2110acdb215c38c840a44"),
      privKey: hexToArrayBuffer("10c67bcb1f4978da2a40439bdef162c118ca16beb5424192c96f9803ade20e6c"),
    },
    signature: hexToArrayBuffer("60e9bcfc3d489d1c301265db471fe8cf513b9d6fd26880023c629ecad7f44bb98e044d25e197ae01dd9d3a079a6dbab17116c706271fff6f174f2e65dddbd58a"),
  }

  bobStore.put('registrationId', 1002)
  bobStore.put('identityKey', bobIdentityKey)
  bobStore.storePreKey(bobPreKey.keyId, bobPreKey.keyPair)
  bobStore.storeSignedPreKey(bobSignedPreKey.keyId, bobSignedPreKey.keyPair)

  const preKeyBundle: DeviceType = {
    identityKey: bobIdentityKey.pubKey,
    registrationId: 1002,
    preKey: {
      keyId: bobPreKey.keyId,
      publicKey: bobPreKey.keyPair.pubKey,
    },
    signedPreKey: {
      keyId: bobSignedPreKey.keyId,
      publicKey: bobSignedPreKey.keyPair.pubKey,
      signature: bobSignedPreKey.signature,
    }
  }

  const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
  await builder.processPreKey(preKeyBundle)

  const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
  const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS)

  const originalMessage = binaryStringToArrayBuffer('Hello world!')

  const ciphertext = await aliceSessionCipher.encrypt(originalMessage)
  console.log('ciphertext', ciphertext)

  const plaintext = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body!, 'binary')
  console.log('plaintext', plaintext)
})()

function hexToArrayBuffer(hex: string) {
  return uint8ArrayToArrayBuffer(Buffer.from(hex, "hex"))
}