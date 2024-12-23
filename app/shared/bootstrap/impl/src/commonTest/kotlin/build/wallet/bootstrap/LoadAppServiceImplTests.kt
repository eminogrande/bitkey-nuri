package build.wallet.bootstrap

import build.wallet.account.AccountServiceFake
import build.wallet.account.AccountStatus
import build.wallet.account.AccountStatus.ActiveAccount
import build.wallet.auth.FullAccountAuthKeyRotationServiceMock
import build.wallet.auth.PendingAuthKeyRotationAttempt
import build.wallet.bitkey.auth.AppAuthPublicKeysMock
import build.wallet.bitkey.keybox.FullAccountMock
import build.wallet.bitkey.keybox.LiteAccountMock
import build.wallet.bitkey.keybox.OnboardingSoftwareAccountMock
import build.wallet.bitkey.keybox.SoftwareAccountMock
import build.wallet.coroutines.turbine.turbines
import build.wallet.feature.FeatureFlagServiceFake
import com.github.michaelbull.result.Ok
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds

class LoadAppServiceImplTests : FunSpec({
  val featureFlagService = FeatureFlagServiceFake()
  val accountService = AccountServiceFake()
  val fullAccountAuthKeyRotationService = FullAccountAuthKeyRotationServiceMock(turbines::create)
  val service = LoadAppServiceImpl(
    featureFlagService,
    accountService,
    fullAccountAuthKeyRotationService
  )

  beforeTest {
    accountService.reset()
    featureFlagService.reset()
    featureFlagService.flagsInitialized.value = true
    fullAccountAuthKeyRotationService.reset()
  }

  test("app state is not returned until feature flags are initialized") {
    featureFlagService.flagsInitialized.value = false

    accountService.accountState.value = Ok(AccountStatus.NoAccount)

    val job = async {
      service.loadAppState()
    }

    // Ensure that the`loadAppState` is suspended because feature flags are not initialized yet.
    delay(50.milliseconds)
    job.isCompleted.shouldBeFalse()

    // Now that feature flags are initialized, the `loadAppState` should return the app state.
    featureFlagService.flagsInitialized.value = true
    job.await().shouldBe(AppState.Undetermined)
    job.isCompleted.shouldBeTrue()
  }

  context("has no active or onboarding account") {
    test("undetermined app state") {
      accountService.accountState.value = Ok(AccountStatus.NoAccount)

      service.loadAppState().shouldBe(AppState.Undetermined)
    }
  }

  context("has active lite account") {
    test("undetermined app state") {
      accountService.accountState.value = Ok(ActiveAccount(LiteAccountMock))

      service.loadAppState().shouldBe(AppState.Undetermined)
    }
  }

  context("has onboarding full account") {
    test("undetermined app state") {
      accountService.accountState.value = Ok(
        AccountStatus.OnboardingAccount(FullAccountMock)
      )

      service.loadAppState().shouldBe(AppState.Undetermined)
    }
  }

  context("has onboarding lite account") {
    test("undetermined app state") {
      accountService.accountState.value = Ok(
        AccountStatus.OnboardingAccount(LiteAccountMock)
      )

      service.loadAppState().shouldBe(AppState.Undetermined)
    }
  }

  context("has onboarding software account") {
    test("undermined app state") {
      accountService.accountState.value = Ok(
        AccountStatus.OnboardingAccount(OnboardingSoftwareAccountMock)
      )

      service.loadAppState().shouldBe(AppState.Undetermined)
    }
  }

  context("has active full account") {
    test("no pending auth key rotation attempt") {
      accountService.accountState.value = Ok(ActiveAccount(FullAccountMock))

      service.loadAppState().shouldBe(
        AppState.HasActiveFullAccount(
          account = FullAccountMock,
          pendingAuthKeyRotation = null
        )
      )
    }

    test("has pending auth key rotation attempt") {
      accountService.accountState.value = Ok(ActiveAccount(FullAccountMock))

      val authKeyRotationAttempt =
        PendingAuthKeyRotationAttempt.IncompleteAttempt(AppAuthPublicKeysMock)
      fullAccountAuthKeyRotationService.pendingKeyRotationAttempt.value = authKeyRotationAttempt

      service.loadAppState().shouldBe(
        AppState.HasActiveFullAccount(
          account = FullAccountMock,
          pendingAuthKeyRotation = authKeyRotationAttempt
        )
      )
    }
  }

  test("has active software account") {
    accountService.accountState.value = Ok(ActiveAccount(SoftwareAccountMock))

    service.loadAppState().shouldBe(
      AppState.HasActiveSoftwareAccount(
        account = SoftwareAccountMock
      )
    )
  }
})
