package build.wallet.statemachine.settings.full.device.fingerprints

import app.cash.turbine.plusAssign
import build.wallet.compose.collections.immutableListOf
import build.wallet.coroutines.turbine.turbines
import build.wallet.firmware.EnrolledFingerprints
import build.wallet.firmware.FingerprintHandle
import build.wallet.nfc.NfcCommandsMock
import build.wallet.nfc.NfcSessionFake
import build.wallet.statemachine.ScreenStateMachineMock
import build.wallet.statemachine.account.create.full.hardware.PairNewHardwareBodyModel
import build.wallet.statemachine.core.ScreenModel
import build.wallet.statemachine.core.StateMachineTester
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.test
import build.wallet.statemachine.nfc.NfcSessionUIStateMachine
import build.wallet.statemachine.nfc.NfcSessionUIStateMachineProps
import build.wallet.statemachine.ui.awaitBody
import build.wallet.statemachine.ui.awaitBodyMock
import build.wallet.statemachine.ui.clickPrimaryButton
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class EnrollingFingerprintUiStateMachineImplTests : FunSpec({
  val stateMachine = EnrollingFingerprintUiStateMachineImpl(
    nfcSessionUIStateMachine =
      object : NfcSessionUIStateMachine, ScreenStateMachineMock<NfcSessionUIStateMachineProps<*>>(
        "nfc fingerprints"
      ) {},
    fingerprintNfcCommands = FingerprintNfcCommandsImpl()
  )

  val onCancelCalls = turbines.create<Unit>("on cancel calls")
  val onSuccessCalls = turbines.create<EnrolledFingerprints>("on success calls")

  val fingerprintHandle = FingerprintHandle(index = 2, label = "Right Thumb")
  val props = EnrollingFingerprintProps(
    onCancel = { onCancelCalls += Unit },
    onSuccess = { onSuccessCalls += it },
    fingerprintHandle = fingerprintHandle,
    enrolledFingerprints = EnrolledFingerprints(
      maxCount = 3,
      fingerprintHandles = immutableListOf(fingerprintHandle)
    )
  )

  val nfcCommandsMock = NfcCommandsMock(turbines::create)

  test("start enrollment then cancel") {
    stateMachine.test(props) {
      awaitBodyMock<NfcSessionUIStateMachineProps<*>> {
        session(NfcSessionFake(), nfcCommandsMock)
        onCancel()
      }

      nfcCommandsMock.awaitEnrollmentNfcCommands()

      onCancelCalls.awaitItem().shouldBe(Unit)
    }
  }

  test("cancelling confirmation goes back to instructions") {
    stateMachine.test(props) {
      startEnrollmentAndTapSaveFingerprint(nfcCommandsMock)
      awaitBodyMock<NfcSessionUIStateMachineProps<EnrollmentStatusResult>> {
        session(NfcSessionFake(), nfcCommandsMock)
        onCancel()
      }

      // Check that the most recent fingerprints are retrieved
      nfcCommandsMock.getEnrolledFingerprintsCalls.awaitItem()

      awaitBody<PairNewHardwareBodyModel> {
        header.headline.shouldBe("Add a new fingerprint")
      }
    }
  }

  test("backing out of instructions invokes props.onCancel") {
    stateMachine.test(props) {
      awaitBodyMock<NfcSessionUIStateMachineProps<Boolean>> {
        session(NfcSessionFake(), nfcCommandsMock)
        onSuccess(true)
      }

      nfcCommandsMock.awaitEnrollmentNfcCommands()

      // See the fingerprint instructions and tap the "Save fingerprint" button, which prompts to
      // tap again for enrollment status
      awaitBody<PairNewHardwareBodyModel> {
        header.headline.shouldBe("Add a new fingerprint")
        onBack.invoke()
      }

      onCancelCalls.awaitItem().shouldBe(Unit)
    }
  }

  test("successful enrollment returns latest fingerprints") {
    stateMachine.test(props) {
      startEnrollmentAndTapSaveFingerprint(nfcCommandsMock)

      val enrolledFingerprints = EnrolledFingerprints(
        maxCount = 3,
        fingerprintHandles = immutableListOf(
          FingerprintHandle(index = 0, label = "Left Thumb"),
          FingerprintHandle(index = 2, label = "Right Thumb")
        )
      )
      awaitBodyMock<NfcSessionUIStateMachineProps<EnrollmentStatusResult>> {
        session(NfcSessionFake(), nfcCommandsMock)
        onSuccess(EnrollmentStatusResult.Complete(enrolledFingerprints))
      }

      nfcCommandsMock.getEnrolledFingerprintsCalls.awaitItem()
      onSuccessCalls.awaitItem().shouldBe(enrolledFingerprints)
    }
  }

  test("enrollment incomplete shows an error") {
    stateMachine.test(props) {
      startEnrollmentAndTapSaveFingerprint(nfcCommandsMock)

      awaitBodyMock<NfcSessionUIStateMachineProps<EnrollmentStatusResult>> {
        session(NfcSessionFake(), nfcCommandsMock)
        onSuccess(EnrollmentStatusResult.Incomplete)
      }

      nfcCommandsMock.getEnrolledFingerprintsCalls.awaitItem()

      with(awaitItem()) {
        // See the error overlay
        bottomSheetModel.shouldNotBeNull()
          .body.shouldBeInstanceOf<FormBodyModel>().apply {
            header.shouldNotBeNull()
              .headline.shouldBe("Incomplete Fingerprint Scan")

            // Close error overlay
            clickPrimaryButton()
          }
      }

      awaitBody<PairNewHardwareBodyModel> {
        header.headline.shouldBe("Add a new fingerprint")
      }
    }
  }
})

private suspend fun StateMachineTester<EnrollingFingerprintProps, ScreenModel>.startEnrollmentAndTapSaveFingerprint(
  nfcCommandsMock: NfcCommandsMock,
) = apply {
  // Start the fingerprint enrollment
  awaitBodyMock<NfcSessionUIStateMachineProps<Boolean>> {
    session(NfcSessionFake(), nfcCommandsMock)
    onSuccess(true)
  }

  nfcCommandsMock.awaitEnrollmentNfcCommands()

  // See the fingerprint instructions and tap the "Save fingerprint" button, which prompts to
  // tap again for enrollment status
  awaitBody<PairNewHardwareBodyModel> {
    header.headline.shouldBe("Add a new fingerprint")
    primaryButton.apply {
      text.shouldBe("Save fingerprint")
      onClick.invoke()
    }
  }
}

private suspend fun NfcCommandsMock.awaitEnrollmentNfcCommands() =
  apply {
    // Confirm that any in-progress enrollment is canceled when starting a new enrollment
    cancelFingerprintEnrollmentCalls.awaitItem().shouldBe(Unit)
    // Check that the most recent fingerprints are retrieved
    getEnrolledFingerprintsCalls.awaitItem()
    // Confirm a new enrollment is started
    startFingerprintEnrollmentCalls.awaitItem()
  }
