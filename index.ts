import { DeviceType, KeyPairType, PreKeyPairType, SessionBuilder, SessionCipher, SignalProtocolAddress, SignedPreKeyPairType } from './src'
import { SignalProtocolStore } from './src/__test__/storage-type'
import { binaryStringToArrayBuffer, uint8ArrayToArrayBuffer } from './src/helpers'

const ALICE_ADDRESS = new SignalProtocolAddress('+14151111111', 1)
const BOB_ADDRESS = new SignalProtocolAddress('+14152222222', 1)

const aliceStore = new SignalProtocolStore()
const bobStore = new SignalProtocolStore();

(async () => {
  const aliceIdentityKey: KeyPairType = {
    pubKey: hexToArrayBuffer("054ee36a5fd60cffac11e4deb45d16a087b3473065fffaf20602b1dec76a715c50"),
    privKey: hexToArrayBuffer("4870ef96dcc0541144d0a76242b4a1870ffd260956ac623fcafa5053934fe752"),
  }

  const alicePreKey: PreKeyPairType = {
    keyId: 2002,
    keyPair: {
      pubKey: hexToArrayBuffer("da0fd388169b69145895588fe0d1a5e616747007572808d449ef2bcd6de69d3d"),
      privKey: hexToArrayBuffer("c0104244993a7f46d637f33499b1c4ad31669a24076b12548daca945afdd8a6a"),
    }
  }

  const aliceSignedPreKey: SignedPreKeyPairType = {
    keyId: 3002,
    keyPair: {
      pubKey: hexToArrayBuffer("85fe55bba744df375b0eef7e3fcaae8175e83545ac32c02f58141cff8a69b271"),
      privKey: hexToArrayBuffer("0889df89b6c9b4ec7f7d7c92a2be79fd1c39c4319751a8f0f11b4bfd3e07d06c"),
    },
    signature: hexToArrayBuffer("929ed1d63073f5364d3ab593fda0dac67ee15949c88fc3ee5f2602083457f666a4a555f544fada952e498577bb1b837e8c4aec7952ed2308c210d5d67652c008"),
  }

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

  aliceStore.put('registrationId', 1001)
  aliceStore.put('identityKey', aliceIdentityKey)
  bobStore.storePreKey(alicePreKey.keyId, alicePreKey.keyPair)
  bobStore.storeSignedPreKey(aliceSignedPreKey.keyId, aliceSignedPreKey.keyPair)

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

  // Alice baixa do servidor o bundle e monta a chain de envio
  // > Aqui o Alice tem a sessão de envio para Bob
  const builder = new SessionBuilder(aliceStore, BOB_ADDRESS)
  await builder.processPreKey(preKeyBundle)

  const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)
  const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS)

  const aliceBobSession1 = await aliceSessionCipher.getRecord(BOB_ADDRESS.toString());
  const bobAliceSession1 = await bobSessionCipher.getRecord(ALICE_ADDRESS.toString());

  // Alice envia para Bob uma PreKeyMessage informando a prekey utilizada para criptografar
  const aliceMessage = binaryStringToArrayBuffer("Hello world from Alice!")
  const ciphertext = await aliceSessionCipher.encrypt(aliceMessage)

  const aliceBobSession11 = await aliceSessionCipher.getRecord(BOB_ADDRESS.toString());

  // Bob pega a preKey utilizada e salva como a chain de recebimento de Alice
  // Bob cria uma chain de envio
  // > Aqui Bob tem a sessão de envio e recebimento de Alice
  const plaintext = await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body!, 'binary')
  console.log("Bob received msg from Alice", plaintext);

  const aliceBobSession2 = await aliceSessionCipher.getRecord(BOB_ADDRESS.toString());
  const bobAliceSession2 = await bobSessionCipher.getRecord(ALICE_ADDRESS.toString());

  // Bob envia para Alice uma SignalMessage informando a ephemeralKey da chain
  const bobMessage = binaryStringToArrayBuffer("Hello world from Bob!")
  const ciphertext2 = await bobSessionCipher.encrypt(bobMessage)

  const bobAliceSession22 = await bobSessionCipher.getRecord(ALICE_ADDRESS.toString());
  // Aqui Alice pega a SignalMessage e monta a sessão de recebimento
  // Aqui Alice tem a sessão de envio e recebimento de alice
  const plaintext2 = await aliceSessionCipher.decryptWhisperMessage(ciphertext2.body!, 'binary')

  const aliceBobSession3 = await aliceSessionCipher.getRecord(BOB_ADDRESS.toString());
  const bobAliceSession3 = await bobSessionCipher.getRecord(ALICE_ADDRESS.toString());

  const ciphertext22 = await bobSessionCipher.encrypt(bobMessage)
  const plaintext22 = await aliceSessionCipher.decryptWhisperMessage(ciphertext22.body!, 'binary')

  const ciphertext33 = await bobSessionCipher.encrypt(bobMessage)
  const plaintext33 = await aliceSessionCipher.decryptWhisperMessage(ciphertext33.body!, 'binary')

  console.log(".")
})()

function hexToArrayBuffer(hex: string) {
  return uint8ArrayToArrayBuffer(Buffer.from(hex, "hex"))
}