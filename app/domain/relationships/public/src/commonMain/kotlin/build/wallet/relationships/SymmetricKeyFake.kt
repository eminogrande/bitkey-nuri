package build.wallet.relationships

import build.wallet.crypto.SymmetricKey
import okio.ByteString

class SymmetricKeyFake(override val raw: ByteString) : SymmetricKey {
  override val length: Int
    get() = raw.size
}
