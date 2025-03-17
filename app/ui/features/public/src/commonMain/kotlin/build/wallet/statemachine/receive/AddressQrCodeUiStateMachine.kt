package build.wallet.statemachine.receive

import build.wallet.bitkey.account.FullAccount
import build.wallet.statemachine.core.BodyModel
import build.wallet.statemachine.core.StateMachine

/**
 * A state machine with receiving functionality (wallet address, QR code).
 */
interface AddressQrCodeUiStateMachine : StateMachine<AddressQrCodeUiProps, BodyModel>

data class AddressQrCodeUiProps(
  val account: FullAccount,
  val onBack: () -> Unit,
)
