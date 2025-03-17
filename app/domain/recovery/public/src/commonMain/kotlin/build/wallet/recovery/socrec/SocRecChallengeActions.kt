package build.wallet.recovery.socrec

import build.wallet.bitkey.f8e.FullAccountId
import build.wallet.bitkey.relationships.ChallengeWrapper
import build.wallet.bitkey.relationships.EndorsedTrustedContact
import build.wallet.encrypt.XCiphertext
import com.github.michaelbull.result.Result
import kotlinx.collections.immutable.ImmutableList

/**
 * Wraps the Social Challenge repository with an account to provide the
 * actions that a user can take on the social challenge screens.
 */
class SocRecChallengeActions(
  private val repository: SocRecChallengeRepository,
  private val accountId: FullAccountId,
  private val isUsingSocRecFakes: Boolean,
) {
  suspend fun startChallenge(
    endorsedTrustedContacts: ImmutableList<EndorsedTrustedContact>,
    sealedDekMap: Map<String, XCiphertext>,
  ): Result<ChallengeWrapper, Error> =
    repository.startChallenge(
      accountId = accountId,
      endorsedTrustedContacts = endorsedTrustedContacts,
      sealedDekMap = sealedDekMap,
      isUsingSocRecFakes = isUsingSocRecFakes
    )

  suspend fun getCurrentChallenge(): Result<ChallengeWrapper?, Error> =
    repository.getCurrentChallenge(
      accountId = accountId,
      isUsingSocRecFakes = isUsingSocRecFakes
    )

  suspend fun getChallengeById(challengeId: String): Result<ChallengeWrapper, Error> =
    repository.getChallengeById(
      challengeId = challengeId,
      accountId = accountId,
      isUsingSocRecFakes = isUsingSocRecFakes
    )
}
