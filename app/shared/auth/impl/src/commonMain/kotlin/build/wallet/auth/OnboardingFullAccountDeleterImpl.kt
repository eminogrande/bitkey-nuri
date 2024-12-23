package build.wallet.auth

import build.wallet.account.AccountService
import build.wallet.bitkey.f8e.FullAccountId
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.f8e.F8eEnvironment
import build.wallet.f8e.auth.HwFactorProofOfPossession
import build.wallet.f8e.onboarding.DeleteOnboardingFullAccountF8eClient
import build.wallet.keybox.KeyboxDao
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding

@BitkeyInject(AppScope::class)
class OnboardingFullAccountDeleterImpl(
  private val accountService: AccountService,
  private val keyboxDao: KeyboxDao,
  private val deleteOnboardingFullAccountF8eClient: DeleteOnboardingFullAccountF8eClient,
) : OnboardingFullAccountDeleter {
  override suspend fun deleteAccount(
    fullAccountId: FullAccountId,
    f8eEnvironment: F8eEnvironment,
    hardwareProofOfPossession: HwFactorProofOfPossession,
  ): Result<Unit, Error> =
    coroutineBinding {
      deleteOnboardingFullAccountF8eClient.deleteOnboardingFullAccount(
        f8eEnvironment,
        fullAccountId,
        hardwareProofOfPossession
      ).bind()
      accountService.clear().bind()
      keyboxDao.clear().bind()
    }
}
