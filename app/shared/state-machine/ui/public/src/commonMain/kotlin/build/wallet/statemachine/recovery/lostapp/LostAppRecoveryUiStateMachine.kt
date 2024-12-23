package build.wallet.statemachine.recovery.lostapp

import androidx.compose.runtime.Composable
import build.wallet.debug.DebugOptions
import build.wallet.di.ActivityScope
import build.wallet.di.BitkeyInject
import build.wallet.statemachine.core.ScreenModel
import build.wallet.statemachine.core.ScreenPresentationStyle.Root
import build.wallet.statemachine.core.StateMachine
import build.wallet.statemachine.data.recovery.lostapp.LostAppRecoveryData
import build.wallet.statemachine.data.recovery.lostapp.LostAppRecoveryData.LostAppRecoveryHaveNotStartedData
import build.wallet.statemachine.data.recovery.lostapp.LostAppRecoveryData.LostAppRecoveryInProgressData
import build.wallet.statemachine.recovery.RecoveryInProgressUiProps
import build.wallet.statemachine.recovery.RecoveryInProgressUiStateMachine

/**
 * The top level recovery UI state machine within the onboarding flow. Houses both the cloud
 * recovery and lost app recovery experiences.
 */
interface LostAppRecoveryUiStateMachine : StateMachine<LostAppRecoveryUiProps, ScreenModel>

data class LostAppRecoveryUiProps(
  val recoveryData: LostAppRecoveryData,
  val debugOptions: DebugOptions,
)

@BitkeyInject(ActivityScope::class)
class LostAppRecoveryUiStateMachineImpl(
  private val lostAppRecoveryHaveNotStartedDataStateMachine:
    LostAppRecoveryHaveNotStartedUiStateMachine,
  private val recoveryInProgressUiStateMachine: RecoveryInProgressUiStateMachine,
) : LostAppRecoveryUiStateMachine {
  @Composable
  override fun model(props: LostAppRecoveryUiProps): ScreenModel {
    return when (val recoveryData = props.recoveryData) {
      is LostAppRecoveryHaveNotStartedData ->
        lostAppRecoveryHaveNotStartedDataStateMachine.model(
          LostAppRecoveryHaveNotStartedUiProps(
            notUndergoingRecoveryData = recoveryData,
            debugOptions = props.debugOptions
          )
        )

      is LostAppRecoveryInProgressData ->
        recoveryInProgressUiStateMachine.model(
          RecoveryInProgressUiProps(
            presentationStyle = Root,
            recoveryInProgressData = recoveryData.recoveryInProgressData,
            fullAccountConfig = props.debugOptions.toFullAccountConfig()
          )
        )
    }
  }
}
