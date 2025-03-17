package build.wallet.statemachine.moneyhome.card.sweep

import build.wallet.statemachine.core.StateMachine
import build.wallet.statemachine.moneyhome.card.CardModel

/**
 * Card used to notify the user that they have funds in an inactive wallet
 * and should sweep them to an active wallet.
 */
interface StartSweepCardUiStateMachine : StateMachine<StartSweepCardUiProps, CardModel?>

data class StartSweepCardUiProps(
  /**
   * Invoked when the user clicks on the card to start a sweep.
   */
  val onStartSweepClicked: () -> Unit,
)
