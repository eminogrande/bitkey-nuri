package bitkey.ui.screens.securityhub

import bitkey.securitycenter.SecurityActionRecommendation.*
import bitkey.securitycenter.SecurityActionsServiceFake
import bitkey.ui.framework.test
import build.wallet.bitkey.keybox.FullAccountMock
import build.wallet.compose.collections.immutableListOf
import build.wallet.fwup.FirmwareDataPendingUpdateMock
import build.wallet.fwup.FirmwareDataServiceFake
import build.wallet.navigation.v1.NavigationScreenId
import build.wallet.router.Router
import build.wallet.statemachine.StateMachineMock
import build.wallet.statemachine.cloud.health.CloudBackupHealthDashboardScreen
import build.wallet.statemachine.data.recovery.losthardware.LostHardwareRecoveryDataMock
import build.wallet.statemachine.fwup.FwupScreen
import build.wallet.statemachine.moneyhome.card.CardModel
import build.wallet.statemachine.recovery.hardware.HardwareRecoveryStatusCardUiProps
import build.wallet.statemachine.recovery.hardware.HardwareRecoveryStatusCardUiStateMachine
import build.wallet.statemachine.recovery.socrec.RecoveryContactCardsUiProps
import build.wallet.statemachine.recovery.socrec.RecoveryContactCardsUiStateMachine
import build.wallet.statemachine.settings.full.device.fingerprints.ManagingFingerprintsScreen
import build.wallet.statemachine.status.HomeStatusBannerUiProps
import build.wallet.statemachine.status.HomeStatusBannerUiStateMachine
import build.wallet.statemachine.ui.awaitBody
import build.wallet.time.MinimumLoadingDuration
import build.wallet.ui.model.status.StatusBannerModel
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeTypeOf
import kotlinx.collections.immutable.ImmutableList
import kotlin.time.Duration.Companion.seconds

class SecurityHubPresenterTests : FunSpec({
  val securityActionsService = SecurityActionsServiceFake()

  val firmwareDataService = FirmwareDataServiceFake()
  firmwareDataService.pendingUpdate = FirmwareDataPendingUpdateMock

  val presenter = SecurityHubPresenter(
    securityActionsService = securityActionsService,
    minimumLoadingDuration = MinimumLoadingDuration(0.seconds),
    homeStatusBannerUiStateMachine = object : HomeStatusBannerUiStateMachine,
      StateMachineMock<HomeStatusBannerUiProps, StatusBannerModel?>(initialModel = null) {},
    firmwareDataService = firmwareDataService,
    recoveryContactCardsUiStateMachine = object : RecoveryContactCardsUiStateMachine,
      StateMachineMock<RecoveryContactCardsUiProps, ImmutableList<CardModel>>(
        initialModel = immutableListOf()
      ) {},
    hardwareRecoveryStatusCardUiStateMachine = object : HardwareRecoveryStatusCardUiStateMachine,
      StateMachineMock<HardwareRecoveryStatusCardUiProps, CardModel?>(
        initialModel = null
      ) {}
  )

  beforeTest {
    securityActionsService.clear()
    Router.route = null
  }

  test("clicking firmware update navigates to the correct route") {
    presenter.test(
      SecurityHubScreen(
        account = FullAccountMock,
        hardwareRecoveryData = LostHardwareRecoveryDataMock
      )
    ) {
      // loading security actions
      awaitBody<SecurityHubBodyModel>()

      awaitBody<SecurityHubBodyModel> {
        onRecommendationClick(UPDATE_FIRMWARE)
      }

      it.goToCalls.awaitItem().shouldBeTypeOf<FwupScreen>()
    }
  }

  test("clicking eak navigates to the correct route") {
    presenter.test(SecurityHubScreen(account = FullAccountMock, hardwareRecoveryData = LostHardwareRecoveryDataMock)) {
      // loading security actions
      awaitBody<SecurityHubBodyModel>()

      awaitBody<SecurityHubBodyModel> {
        onRecommendationClick(BACKUP_EAK)
      }

      it.goToCalls.awaitItem().shouldBeTypeOf<CloudBackupHealthDashboardScreen>()
    }
  }

  test("clicking a fingerprint navigates to the correct screen") {
    presenter.test(SecurityHubScreen(account = FullAccountMock, hardwareRecoveryData = LostHardwareRecoveryDataMock)) {
      // loading security actions
      awaitBody<SecurityHubBodyModel>()

      awaitBody<SecurityHubBodyModel> {
        onRecommendationClick(ADD_FINGERPRINTS)
      }

      it.goToCalls.awaitItem().shouldBeTypeOf<ManagingFingerprintsScreen>()
    }
  }

  test("recommendation maps to the correct navigation id") {
    entries.forEach { recommendation ->
      when (recommendation) {
        BACKUP_MOBILE_KEY -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_MOBILE_KEY_BACKUP)
        BACKUP_EAK -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_EAK_BACKUP_HEALTH)
        ADD_FINGERPRINTS -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_MANAGE_FINGERPRINTS)
        ADD_TRUSTED_CONTACTS -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_MANAGE_RECOVERY_CONTACTS)
        ENABLE_CRITICAL_ALERTS, ENABLE_PUSH_NOTIFICATIONS, ENABLE_SMS_NOTIFICATIONS,
        ENABLE_EMAIL_NOTIFICATIONS,
        -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_MANAGE_CRITICAL_ALERTS)
        ADD_BENEFICIARY -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_MANAGE_INHERITANCE)
        SETUP_BIOMETRICS -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_MANAGE_BIOMETRIC)
        PAIR_HARDWARE_DEVICE -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_PAIR_DEVICE)
        UPDATE_FIRMWARE -> recommendation.navigationScreenId()
          .shouldBe(NavigationScreenId.NAVIGATION_SCREEN_ID_UPDATE_FIRMWARE)
      }
    }
  }
})
