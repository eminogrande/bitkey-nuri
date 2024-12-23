package build.wallet.statemachine.account

import build.wallet.coroutines.turbine.turbines
import build.wallet.emergencyaccesskit.EmergencyAccessKitAssociation
import build.wallet.emergencyaccesskit.EmergencyAccessKitDataProviderFake
import build.wallet.feature.FeatureFlagDaoFake
import build.wallet.feature.flags.SoftwareWalletIsEnabledFeatureFlag
import build.wallet.feature.setFlagValue
import build.wallet.platform.config.AppVariant
import build.wallet.platform.device.DeviceInfoProviderMock
import build.wallet.statemachine.ScreenStateMachineMock
import build.wallet.statemachine.account.create.CreateSoftwareWalletProps
import build.wallet.statemachine.account.create.CreateSoftwareWalletUiStateMachine
import build.wallet.statemachine.core.awaitScreenWithBody
import build.wallet.statemachine.core.awaitScreenWithBodyModelMock
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.form.FormMainContentModel
import build.wallet.statemachine.core.test
import build.wallet.statemachine.data.keybox.AccountData.NoActiveAccountData.GettingStartedData
import build.wallet.statemachine.demo.DemoModeConfigUiProps
import build.wallet.statemachine.demo.DemoModeConfigUiStateMachine
import build.wallet.statemachine.dev.DebugMenuProps
import build.wallet.statemachine.dev.DebugMenuStateMachine
import build.wallet.statemachine.ui.clickPrimaryButton
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeTypeOf

class ChooseAccountAccessUiStateMachineImplTests : FunSpec({

  val emergencyAccessKitDataProvider = EmergencyAccessKitDataProviderFake()
  val featureFlagDao = FeatureFlagDaoFake()
  val softwareWalletIsEnabledFeatureFlag = SoftwareWalletIsEnabledFeatureFlag(featureFlagDao)
  val createSoftwareWalletUiStateMachine = object : CreateSoftwareWalletUiStateMachine,
    ScreenStateMachineMock<CreateSoftwareWalletProps>(
      id = "create-software-wallet"
    ) {}

  fun buildStateMachine(appVariant: AppVariant) =
    ChooseAccountAccessUiStateMachineImpl(
      appVariant = appVariant,
      debugMenuStateMachine = object : DebugMenuStateMachine,
        ScreenStateMachineMock<DebugMenuProps>(
          id = "debug-menu"
        ) {},
      demoModeConfigUiStateMachine = object : DemoModeConfigUiStateMachine,
        ScreenStateMachineMock<DemoModeConfigUiProps>(
          id = "demo-mode"
        ) {},
      deviceInfoProvider = DeviceInfoProviderMock(),
      emergencyAccessKitDataProvider = emergencyAccessKitDataProvider,
      softwareWalletIsEnabledFeatureFlag = softwareWalletIsEnabledFeatureFlag,
      createSoftwareWalletUiStateMachine = createSoftwareWalletUiStateMachine
    )

  val stateMachine = buildStateMachine(appVariant = AppVariant.Development)

  val startRecoveryCalls = turbines.create<Unit>("startRecovery calls")
  val startFullAccountCreationCalls = turbines.create<Unit>("startFullAccountCreation calls")
  val startLiteAccountCreationCalls = turbines.create<Unit>("startLiteAccountCreation calls")
  val startEmergencyAccessRecoveryCalls =
    turbines.create<Unit>("startEmergencyAccessRecovery calls")
  val wipeExistingDeviceCalls = turbines.create<Unit>("wipeExistingDevice calls")

  val props = ChooseAccountAccessUiProps(
    chooseAccountAccessData = GettingStartedData(
      startRecovery = { startRecoveryCalls.add(Unit) },
      startFullAccountCreation = { startFullAccountCreationCalls.add(Unit) },
      startLiteAccountCreation = { startLiteAccountCreationCalls.add(Unit) },
      startEmergencyAccessRecovery = { startEmergencyAccessRecoveryCalls.add(Unit) },
      wipeExistingDevice = { wipeExistingDeviceCalls.add(Unit) },
      isNavigatingBack = false
    ),
    onSoftwareWalletCreated = {}
  )

  beforeTest {
    emergencyAccessKitDataProvider.reset()
  }

  test("initial state") {
    stateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel>()
    }
  }

  test("create full account") {
    stateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel> {
        buttons.first().shouldNotBeNull().onClick()
      }

      startFullAccountCreationCalls.awaitItem()
    }
  }

  test("create full account - is navigating back") {
    stateMachine.test(props.copy(props.chooseAccountAccessData.copy(isNavigatingBack = true))) {
      awaitScreenWithBody<ChooseAccountAccessModel>()
    }
  }

  test("create lite account") {
    stateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel> {
        buttons[1].shouldNotBeNull().onClick()
      }

      awaitScreenWithBody<FormBodyModel> {
        mainContentList.first()
          .shouldBeTypeOf<FormMainContentModel.ListGroup>()
          .listGroupModel
          .items[0]
          .onClick.shouldNotBeNull().invoke()
      }

      // Click through the BeTrustedContactIntroductionModel
      awaitScreenWithBody<FormBodyModel> {
        clickPrimaryButton()
      }

      startLiteAccountCreationCalls.awaitItem()
    }
  }

  test("recover wallet") {
    stateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel> {
        buttons[1].shouldNotBeNull().onClick()
      }

      awaitScreenWithBody<FormBodyModel> {
        mainContentList.first()
          .shouldBeTypeOf<FormMainContentModel.ListGroup>()
          .listGroupModel
          .items[1]
          .also {
            it.title.shouldBe("Restore your wallet")
          }
          .onClick.shouldNotBeNull().invoke()
      }

      startRecoveryCalls.awaitItem()
    }
  }

  context("software wallet flag is on") {
    softwareWalletIsEnabledFeatureFlag.setFlagValue(true)

    test("create hardware and software wallet options are shown") {
      stateMachine.test(props) {
        awaitScreenWithBody<ChooseAccountAccessModel> {
          buttons[0].shouldNotBeNull().onClick()
        }

        awaitScreenWithBody<FormBodyModel> {
          val buttons = mainContentList
            .first()
            .shouldBeTypeOf<FormMainContentModel.ListGroup>()
            .listGroupModel

          buttons.items[0]
            .title
            .shouldBe("Use Bitkey hardware")

          buttons.items[1]
            .title
            .shouldBe("Use this device")
        }
      }
    }
  }

  test("wipe existing device") {
    stateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel> {
        buttons[1].shouldNotBeNull().onClick()
      }

      awaitScreenWithBody<FormBodyModel> {
        mainContentList.first()
          .shouldBeTypeOf<FormMainContentModel.ListGroup>()
          .listGroupModel
          .items[2]
          .also {
            it.title.shouldBe("Wipe an existing device")
          }
          .onClick.shouldNotBeNull().invoke()
      }

      wipeExistingDeviceCalls.awaitItem()
    }
  }

  test("emergency access recovery button shows in eak builds") {
    emergencyAccessKitDataProvider.eakAssociation = EmergencyAccessKitAssociation.EakBuild

    stateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel> {
        buttons[1].shouldNotBeNull().onClick()
      }

      awaitScreenWithBody<FormBodyModel> {
        mainContentList.first()
          .shouldBeTypeOf<FormMainContentModel.ListGroup>()
          .listGroupModel
          .items[0]
          .also {
            it.title.shouldBe("Import using Emergency Access Kit")
          }
          .onClick.shouldNotBeNull().invoke()
      }

      startEmergencyAccessRecoveryCalls.awaitItem()
    }
  }

  test("shows debug menu in development build") {
    stateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel> {
        onLogoClick()
      }
      awaitScreenWithBodyModelMock<DebugMenuProps> {
        onClose()
      }
      awaitScreenWithBody<ChooseAccountAccessModel>()
    }
  }

  test("shows demo mode in customer build") {
    val customerStateMachine = buildStateMachine(AppVariant.Customer)
    customerStateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel> {
        onLogoClick()
      }
      awaitScreenWithBodyModelMock<DemoModeConfigUiProps> {
        onBack()
      }
      awaitScreenWithBody<ChooseAccountAccessModel>()
    }
  }

  test("EAK disabled paths") {
    emergencyAccessKitDataProvider.eakAssociation = EmergencyAccessKitAssociation.EakBuild

    stateMachine.test(props) {
      awaitScreenWithBody<ChooseAccountAccessModel> {
        buttons[0].shouldNotBeNull().onClick()
      }
      awaitItem().should {
        it.alertModel.shouldNotBeNull()
        it.body.shouldBeTypeOf<ChooseAccountAccessModel>()
          .buttons[1].onClick()
      }
      awaitScreenWithBody<FormBodyModel> {
        // Only "Import using Emergency Access Kit" is included in the EAK build.
        mainContentList.first()
          .shouldBeTypeOf<FormMainContentModel.ListGroup>()
          .listGroupModel
          .items[0]
          .also {
            it.title.shouldBe("Import using Emergency Access Kit")
          }
          .onClick.shouldNotBeNull().invoke()
      }
      startEmergencyAccessRecoveryCalls.awaitItem()
    }
  }
})
