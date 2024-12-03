package build.wallet.auth

import build.wallet.bitkey.app.AppAuthPublicKeys
import build.wallet.database.BitkeyDatabaseProvider
import build.wallet.db.DbError
import build.wallet.logging.*
import build.wallet.logging.logFailure
import build.wallet.mapResult
import build.wallet.sqldelight.asFlowOfOneOrNull
import build.wallet.sqldelight.awaitTransaction
import com.github.michaelbull.result.Result
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flow

class AuthKeyRotationAttemptDaoImpl(
  private val databaseProvider: BitkeyDatabaseProvider,
) : AuthKeyRotationAttemptDao {
  override fun observeAuthKeyRotationAttemptState(): Flow<Result<AuthKeyRotationAttemptDaoState, Throwable>> {
    return flow {
      databaseProvider.database()
        .authKeyRotationAttemptQueries
        .getAuthKeyRotationAttempt()
        .asFlowOfOneOrNull()
        .mapResult { attempt ->
          if (attempt != null) {
            val appGlobalAuthPublicKey = attempt.destinationAppGlobalAuthKey
            val appRecoveryAuthPublicKey = attempt.destinationAppRecoveryAuthKey
            val appGlobalAuthKeyHwSignature = attempt.destinationAppGlobalAuthKeyHwSignature

            if (appGlobalAuthPublicKey != null && appRecoveryAuthPublicKey != null && appGlobalAuthKeyHwSignature != null) {
              AuthKeyRotationAttemptDaoState.AuthKeysWritten(
                appAuthPublicKeys = AppAuthPublicKeys(
                  appGlobalAuthPublicKey = appGlobalAuthPublicKey,
                  appRecoveryAuthPublicKey = appRecoveryAuthPublicKey,
                  appGlobalAuthKeyHwSignature = appGlobalAuthKeyHwSignature
                )
              )
            } else {
              if (appGlobalAuthPublicKey != null) {
                logError {
                  "Auth key rotation proposal found, but global auth key wasn't null."
                }
              }
              if (appRecoveryAuthPublicKey != null) {
                logError {
                  "Auth key rotation proposal found, but recovery auth key wasn't null."
                }
              }
              if (appGlobalAuthKeyHwSignature != null) {
                logError {
                  "Auth key rotation proposal found, but app global auth key hardware signature wasn't null."
                }
              }
              AuthKeyRotationAttemptDaoState.KeyRotationProposalWritten
            }
          } else {
            AuthKeyRotationAttemptDaoState.NoAttemptInProgress
          }
        }
        .distinctUntilChanged()
        .collect(::emit)
    }
  }

  override suspend fun setKeyRotationProposal(): Result<Unit, DbError> {
    return databaseProvider.database().awaitTransaction {
      authKeyRotationAttemptQueries.setKeyRotationProposal()
    }.logFailure { "Error setting key rotation proposal." }
  }

  override suspend fun setAuthKeysWritten(
    appAuthPublicKeys: AppAuthPublicKeys,
  ): Result<Unit, DbError> {
    return databaseProvider.database().awaitTransaction {
      authKeyRotationAttemptQueries.clear()
      authKeyRotationAttemptQueries.setAuthKeyCreated(
        destinationAppGlobalAuthKey = appAuthPublicKeys.appGlobalAuthPublicKey,
        destinationAppRecoveryAuthKey = appAuthPublicKeys.appRecoveryAuthPublicKey,
        destinationAppGlobalAuthKeyHwSignature = appAuthPublicKeys.appGlobalAuthKeyHwSignature
      )
    }.logFailure { "Error setting auth keys written." }
  }

  override suspend fun clear(): Result<Unit, DbError> {
    return databaseProvider.database().awaitTransaction {
      authKeyRotationAttemptQueries.clear()
    }.logFailure { "Error clearing auth key rotation attempt" }
  }
}
