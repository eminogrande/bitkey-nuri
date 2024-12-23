package build.wallet.onboarding

import build.wallet.cloud.backup.csek.SealedCsek
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.logging.logFailure
import build.wallet.serialization.hex.decodeHexWithResult
import build.wallet.store.EncryptedKeyValueStoreFactory
import build.wallet.store.clearWithResult
import build.wallet.store.getStringOrNullWithResult
import build.wallet.store.putStringWithResult
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding

/**
 * Persists sealed CSEKs in a secure store, encoded as hex string.
 */

@BitkeyInject(AppScope::class)
class OnboardingKeyboxSealedCsekDaoImpl(
  private val encryptedKeyValueStoreFactory: EncryptedKeyValueStoreFactory,
) : OnboardingKeyboxSealedCsekDao {
  private suspend fun secureStore() =
    encryptedKeyValueStoreFactory.getOrCreate(storeName = STORE_NAME)

  override suspend fun get(): Result<SealedCsek?, Throwable> =
    coroutineBinding {
      secureStore()
        .getStringOrNullWithResult(key = KEY_SEALED_CSEK)
        .bind()
        ?.decodeHexWithResult()
        ?.bind()
    }.logFailure { "Failed to get $KEY_SEALED_CSEK from $STORE_NAME" }

  override suspend fun set(value: SealedCsek): Result<Unit, Throwable> {
    return secureStore()
      .putStringWithResult(key = KEY_SEALED_CSEK, value = value.hex())
      .logFailure { "Failed to set $KEY_SEALED_CSEK in $STORE_NAME" }
  }

  override suspend fun clear(): Result<Unit, Throwable> {
    return secureStore()
      .clearWithResult()
      .logFailure { "Failed to clear SealedCsekStore" }
  }

  private companion object {
    // Changing these values is a breaking change
    // These should only be changed with a migration plan
    const val STORE_NAME = "SealedCsekStore"
    const val KEY_SEALED_CSEK = "sealed-csek-key"
  }
}
