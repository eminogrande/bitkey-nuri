import Foundation
import Shared
import Testing

@testable import Wallet

struct Secp256k1SharedSecretImplTests {

    @Test
    func deriveSharedSecret() throws {
        let keyGenerator = Secp256k1KeyGeneratorImpl()
        let sharedSecret = Secp256k1SharedSecretImpl()
        let aliceKeypair = try keyGenerator.generateKeypair()
        let alicePrivateKey = aliceKeypair.privateKey
        let alicePublicKey = aliceKeypair.publicKey
        let bobKeypair = try keyGenerator.generateKeypair()
        let bobPrivateKey = bobKeypair.privateKey
        let bobPublicKey = bobKeypair.publicKey

        let aliceSharedSecretBytes = sharedSecret.deriveSharedSecret(
            privateKey: alicePrivateKey,
            publicKey: bobPublicKey
        )
        let bobSharedSecretBytes = sharedSecret.deriveSharedSecret(
            privateKey: bobPrivateKey,
            publicKey: alicePublicKey
        )
        let oddSharedSecretBytes = sharedSecret.deriveSharedSecret(
            privateKey: alicePrivateKey,
            publicKey: alicePublicKey
        )

        #expect(aliceSharedSecretBytes == bobSharedSecretBytes)
        #expect(aliceSharedSecretBytes != oddSharedSecretBytes)
    }
}
