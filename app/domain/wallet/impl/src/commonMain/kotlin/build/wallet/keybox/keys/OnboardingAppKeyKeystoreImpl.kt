package build.wallet.keybox.keys

import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitkey.app.AppGlobalAuthKey
import build.wallet.bitkey.app.AppKeyBundle
import build.wallet.bitkey.app.AppRecoveryAuthKey
import build.wallet.bitkey.app.AppSpendingPublicKey
import build.wallet.crypto.PublicKey
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.store.EncryptedKeyValueStoreFactory
import build.wallet.store.clearWithResult
import com.github.michaelbull.result.Result
import com.russhwolf.settings.ExperimentalSettingsApi

private const val KEYSTORE_KEY = "onboarding-app-keys"
private const val SPENDING_KEY = "spending-key"
private const val APP_GLOBAL_AUTH_KEY = "auth-key"
private const val APP_RECOVERY_AUTH_KEY = "app-recovery-auth-key"
private const val NETWORK_KEY = "network-key"

/**
 * This implementation of [OnboardingAppKeyKeystore] uses [SuspendSettings] to persist app keys
 * during onboarding to allow the data to survive past uninstalls. *note* this behavior only happens
 * on iOS currently
 *
 * @param encryptedKeyValueStoreFactory - factory for creating a store
 */

@OptIn(ExperimentalSettingsApi::class)
@BitkeyInject(AppScope::class)
class OnboardingAppKeyKeystoreImpl(
  private val encryptedKeyValueStoreFactory: EncryptedKeyValueStoreFactory,
) : OnboardingAppKeyKeystore {
  private suspend fun appKeystore() = encryptedKeyValueStoreFactory.getOrCreate(KEYSTORE_KEY)

  override suspend fun persistAppKeys(
    spendingKey: AppSpendingPublicKey,
    globalAuthKey: PublicKey<AppGlobalAuthKey>,
    recoveryAuthKey: PublicKey<AppRecoveryAuthKey>,
    bitcoinNetworkType: BitcoinNetworkType,
  ) {
    val appKeystore = appKeystore()
    appKeystore.putString(SPENDING_KEY, spendingKey.key.dpub)
    appKeystore.putString(APP_GLOBAL_AUTH_KEY, globalAuthKey.value)
    appKeystore.putString(APP_RECOVERY_AUTH_KEY, recoveryAuthKey.value)
    appKeystore.putString(NETWORK_KEY, bitcoinNetworkType.name)
  }

  override suspend fun getAppKeyBundle(
    localId: String,
    network: BitcoinNetworkType,
  ): AppKeyBundle? {
    val appKeystore = appKeystore()
    val spendingKey = appKeystore.getStringOrNull(SPENDING_KEY) ?: return null
    val globalAuthKey = appKeystore.getStringOrNull(APP_GLOBAL_AUTH_KEY) ?: return null
    val recoveryAuthKey = appKeystore.getStringOrNull(APP_RECOVERY_AUTH_KEY) ?: return null
    val bitcoinNetworkTypeName = appKeystore.getStringOrNull(NETWORK_KEY) ?: return null
    val bitcoinNetworkType = BitcoinNetworkType.valueOf(bitcoinNetworkTypeName)

    if (network != bitcoinNetworkType) {
      return null
    }

    return AppKeyBundle(
      localId = localId,
      spendingKey = AppSpendingPublicKey(spendingKey),
      authKey = PublicKey(globalAuthKey),
      networkType = network,
      recoveryAuthKey = PublicKey(recoveryAuthKey)
    )
  }

  override suspend fun clear(): Result<Unit, Throwable> {
    return appKeystore().clearWithResult()
  }
}
