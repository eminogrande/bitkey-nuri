package build.wallet.cloud.backup

import build.wallet.bitcoin.AppPrivateKeyDao
import build.wallet.bitkey.account.LiteAccount
import build.wallet.bitkey.keys.app.AppKey
import build.wallet.bitkey.relationships.DelegatedDecryptionKey
import build.wallet.cloud.backup.LiteAccountCloudBackupCreator.LiteAccountCloudBackupCreatorError.AppRecoveryAuthKeypairRetrievalError
import build.wallet.cloud.backup.LiteAccountCloudBackupCreator.LiteAccountCloudBackupCreatorError.SocRecKeysRetrievalError
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.relationships.RelationshipsKeysRepository
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.toErrorIfNull

@BitkeyInject(AppScope::class)
class LiteAccountCloudBackupCreatorImpl(
  private val relationshipsKeysRepository: RelationshipsKeysRepository,
  private val appPrivateKeyDao: AppPrivateKeyDao,
) : LiteAccountCloudBackupCreator {
  override suspend fun create(
    account: LiteAccount,
  ): Result<CloudBackupV2, LiteAccountCloudBackupCreator.LiteAccountCloudBackupCreatorError> =
    coroutineBinding {
      val delegatedDecryptionKeypair =
        relationshipsKeysRepository.getKeyWithPrivateMaterialOrCreate<DelegatedDecryptionKey>()
          .mapError { SocRecKeysRetrievalError(it) }
          .bind()

      val recoveryAuthPrivateKey =
        appPrivateKeyDao
          .getAsymmetricPrivateKey(account.recoveryAuthKey)
          .toErrorIfNull {
            IllegalStateException("Active recovery app auth private key not found.")
          }
          .mapError { AppRecoveryAuthKeypairRetrievalError(it) }
          .bind()

      val appRecoveryAuthKeypair =
        AppKey(
          publicKey = account.recoveryAuthKey,
          privateKey = recoveryAuthPrivateKey
        )

      CloudBackupV2(
        accountId = account.accountId.serverId,
        f8eEnvironment = account.config.f8eEnvironment,
        isTestAccount = account.config.isTestAccount,
        fullAccountFields = null,
        appRecoveryAuthKeypair = appRecoveryAuthKeypair,
        delegatedDecryptionKeypair = delegatedDecryptionKeypair,
        isUsingSocRecFakes = account.config.isUsingSocRecFakes,
        bitcoinNetworkType = account.config.bitcoinNetworkType
      )
    }
}
