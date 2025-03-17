package build.wallet.recovery.socrec

import build.wallet.bitkey.account.Account
import build.wallet.bitkey.f8e.FullAccountId
import build.wallet.bitkey.relationships.ChallengeWrapper
import build.wallet.bitkey.relationships.EndorsedTrustedContact
import build.wallet.bitkey.socrec.TrustedContactRecoveryPakeKey
import build.wallet.crypto.PublicKey
import build.wallet.encrypt.XCiphertext
import build.wallet.f8e.socrec.models.ChallengeVerificationResponse
import com.github.michaelbull.result.Result
import kotlinx.collections.immutable.ImmutableList
import okio.ByteString

/**
 * Manages the active Social Recovery Challenges for a given account.
 */
interface SocRecChallengeRepository {
  /**
   * Starts a new Social Recovery Challenge for the [account].
   */
  suspend fun startChallenge(
    accountId: FullAccountId,
    endorsedTrustedContacts: ImmutableList<EndorsedTrustedContact>,
    sealedDekMap: Map<String, XCiphertext>,
    isUsingSocRecFakes: Boolean,
  ): Result<ChallengeWrapper, Error>

  /**
   * Get the current active social challenge for this device, if one exists.
   */
  suspend fun getCurrentChallenge(
    accountId: FullAccountId,
    isUsingSocRecFakes: Boolean,
  ): Result<ChallengeWrapper?, Error>

  /**
   * Get a specific social challenge by a specified ID.
   */
  suspend fun getChallengeById(
    challengeId: String,
    accountId: FullAccountId,
    isUsingSocRecFakes: Boolean,
  ): Result<ChallengeWrapper, Error>

  /**
   * Verify the active social challenge by providing the code sent by the protect customer.
   * The response contains the keys necessary for encrypting the shared secret.
   */
  suspend fun verifyChallenge(
    account: Account,
    recoveryRelationshipId: String,
    code: Int,
  ): Result<ChallengeVerificationResponse, Error>

  /**
   * Respond to the social challenge by providing the shared secret for the active challenge
   */
  suspend fun respondToChallenge(
    account: Account,
    socialChallengeId: String,
    trustedContactRecoveryPakePubkey: PublicKey<TrustedContactRecoveryPakeKey>,
    recoveryPakeConfirmation: ByteString,
    resealedDek: XCiphertext,
  ): Result<Unit, Error>
}

/**
 * Wrap the repository in an account to get the performable actions for challenges.
 */
fun SocRecChallengeRepository.toActions(
  accountId: FullAccountId,
  isUsingSocRecFakes: Boolean,
) = SocRecChallengeActions(
  repository = this,
  accountId = accountId,
  isUsingSocRecFakes = isUsingSocRecFakes
)
