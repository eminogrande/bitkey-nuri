package build.wallet.recovery

import build.wallet.auth.*
import build.wallet.auth.AccountCreationError.AccountCreationAuthError
import build.wallet.auth.AccountCreationError.AccountCreationDatabaseError.FailedToSaveAuthTokens
import build.wallet.bitkey.app.AppAuthKey
import build.wallet.bitkey.app.AppAuthPublicKeys
import build.wallet.bitkey.challange.SignedChallenge.HardwareSignedChallenge
import build.wallet.bitkey.f8e.FullAccountId
import build.wallet.bitkey.factor.PhysicalFactor.Hardware
import build.wallet.cloud.backup.csek.SealedCsek
import build.wallet.crypto.PublicKey
import build.wallet.ensure
import build.wallet.f8e.F8eEnvironment
import build.wallet.f8e.recovery.CompleteDelayNotifyF8eClient
import build.wallet.logging.*
import build.wallet.logging.logFailure
import build.wallet.logging.logNetworkFailure
import build.wallet.relationships.RelationshipsService
import build.wallet.time.Delayer
import build.wallet.time.withMinimumDelay
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.onSuccess
import kotlin.time.Duration.Companion.seconds

class RecoveryAuthCompleterImpl(
  private val appAuthKeyMessageSigner: AppAuthKeyMessageSigner,
  private val completeDelayNotifyF8eClient: CompleteDelayNotifyF8eClient,
  private val accountAuthenticator: AccountAuthenticator,
  private val recoverySyncer: RecoverySyncer,
  private val authTokenDao: AuthTokenDao,
  private val relationshipsService: RelationshipsService,
  private val delayer: Delayer,
) : RecoveryAuthCompleter {
  override suspend fun rotateAuthKeys(
    f8eEnvironment: F8eEnvironment,
    fullAccountId: FullAccountId,
    hardwareSignedChallenge: HardwareSignedChallenge,
    destinationAppAuthPubKeys: AppAuthPublicKeys,
    sealedCsek: SealedCsek,
    removeProtectedCustomers: Boolean,
  ): Result<Unit, Throwable> {
    logDebug { "Rotating auth keys for recovery" }

    return coroutineBinding {
      // Hack for W-4377; this entire method needs to take at least 2 seconds, so the last step
      // is performed after this minimum delay because it triggers recompose via recovery change.
      delayer.withMinimumDelay(2.seconds) {
        ensure(hardwareSignedChallenge.signingFactor == Hardware) {
          Error("Expected $hardwareSignedChallenge to be signed with Hardware factor.")
        }

        recoverySyncer
          .setLocalRecoveryProgress(
            LocalRecoveryAttemptProgress.AttemptingCompletion(sealedCsek = sealedCsek)
          ).bind()

        val appSignedChallenge =
          appAuthKeyMessageSigner
            .signChallenge(
              publicKey = destinationAppAuthPubKeys.appGlobalAuthPublicKey,
              challenge = hardwareSignedChallenge.challenge
            )
            .logFailure { "Error signing complete recovery challenge with app auth key." }
            .bind()

        completeDelayNotifyF8eClient
          .complete(
            f8eEnvironment = f8eEnvironment,
            fullAccountId = fullAccountId,
            challenge = hardwareSignedChallenge.challenge.data,
            appSignature = appSignedChallenge.signature,
            hardwareSignature = hardwareSignedChallenge.signature
          )
          .logNetworkFailure { "Error completing recovery with f8e." }
          .bind()

        // TODO(W-4259): Move this out of here since it should come after completion.
        authenticateWithF8eAndStoreAuthTokens(
          accountId = fullAccountId,
          appAuthPublicKey = destinationAppAuthPubKeys.appRecoveryAuthPublicKey,
          f8eEnvironment = f8eEnvironment,
          tokenScope = AuthTokenScope.Recovery
        ).bind()
        authenticateWithF8eAndStoreAuthTokens(
          accountId = fullAccountId,
          appAuthPublicKey = destinationAppAuthPubKeys.appGlobalAuthPublicKey,
          f8eEnvironment = f8eEnvironment,
          tokenScope = AuthTokenScope.Global
        ).bind()

        if (removeProtectedCustomers) {
          relationshipsService
            .getRelationshipsWithoutSyncing(
              fullAccountId,
              f8eEnvironment
            )
            .logFailure { "Error fetching relationships for removal" }
            .onSuccess { relationships ->
              relationships.protectedCustomers.onEach {
                relationshipsService.removeRelationshipWithoutSyncing(
                  accountId = fullAccountId,
                  f8eEnvironment = f8eEnvironment,
                  hardwareProofOfPossession = null,
                  AuthTokenScope.Recovery,
                  it.relationshipId
                ).bind()
              }
            }
        }
      }

      recoverySyncer
        .setLocalRecoveryProgress(
          LocalRecoveryAttemptProgress.RotatedAuthKeys
        ).bind()
    }
  }

  /**
   * Performs auth with f8e using the given [AppAuthPublicKey] and stores the resulting
   * tokens in [AuthTokenDao] keyed by the given [AuthTokenScope]
   */
  private suspend fun authenticateWithF8eAndStoreAuthTokens(
    accountId: FullAccountId,
    appAuthPublicKey: PublicKey<out AppAuthKey>,
    f8eEnvironment: F8eEnvironment,
    tokenScope: AuthTokenScope,
  ): Result<Unit, AccountCreationError> {
    return coroutineBinding {
      val authTokens =
        accountAuthenticator
          .appAuth(
            f8eEnvironment = f8eEnvironment,
            appAuthPublicKey = appAuthPublicKey,
            authTokenScope = tokenScope
          )
          .mapError { AccountCreationAuthError(it) }
          .bind()
          .authTokens

      authTokenDao
        .setTokensOfScope(accountId, authTokens, tokenScope)
        .mapError { FailedToSaveAuthTokens(it) }
        .bind()
    }
  }
}
