package build.wallet.statemachine.recovery.losthardware.initiate

import build.wallet.bitkey.account.FullAccount
import build.wallet.statemachine.core.ScreenModel
import build.wallet.statemachine.core.ScreenPresentationStyle
import build.wallet.statemachine.core.StateMachine
import build.wallet.statemachine.data.recovery.losthardware.LostHardwareRecoveryData.InitiatingLostHardwareRecoveryData

/**
 * UI State Machine for navigating the initiation of lost hardware recovery.
 * Includes instructions screens and pairing new hardware.
 */
interface InitiatingLostHardwareRecoveryUiStateMachine :
  StateMachine<InitiatingLostHardwareRecoveryProps, ScreenModel>

data class InitiatingLostHardwareRecoveryProps(
  val account: FullAccount,
  val screenPresentationStyle: ScreenPresentationStyle,
  val instructionsStyle: InstructionsStyle,
  val initiatingLostHardwareRecoveryData: InitiatingLostHardwareRecoveryData,
  val onFoundHardware: () -> Unit,
  val onExit: () -> Unit,
)
