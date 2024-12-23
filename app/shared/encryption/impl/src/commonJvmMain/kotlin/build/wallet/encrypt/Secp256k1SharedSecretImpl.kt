package build.wallet.encrypt

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.toUByteList
import okio.ByteString
import okio.ByteString.Companion.toByteString
import build.wallet.rust.core.Secp256k1SharedSecret as CoreSecp256k1SharedSecret
import build.wallet.rust.core.SecretKey as CoreSecretKey

@BitkeyInject(AppScope::class)
class Secp256k1SharedSecretImpl : Secp256k1SharedSecret {
  override fun deriveSharedSecret(
    privateKey: Secp256k1PrivateKey,
    publicKey: Secp256k1PublicKey,
  ): ByteString {
    val coreSecretKey = CoreSecretKey(privateKey.bytes.toUByteList())
    val sharedSecret = CoreSecp256k1SharedSecret(publicKey.value, coreSecretKey)
    return sharedSecret.secretBytes().toByteString()
  }
}
