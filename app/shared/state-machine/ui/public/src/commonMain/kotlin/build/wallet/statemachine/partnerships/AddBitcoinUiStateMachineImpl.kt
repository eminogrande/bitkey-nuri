package build.wallet.statemachine.partnerships

import androidx.compose.runtime.*
import build.wallet.money.FiatMoney
import build.wallet.statemachine.core.SheetModel
import build.wallet.statemachine.partnerships.AddBitcoinUiState.*
import build.wallet.statemachine.partnerships.purchase.PartnershipsPurchaseUiProps
import build.wallet.statemachine.partnerships.purchase.PartnershipsPurchaseUiStateMachine
import build.wallet.statemachine.partnerships.transfer.PartnershipsTransferUiProps
import build.wallet.statemachine.partnerships.transfer.PartnershipsTransferUiStateMachine

class AddBitcoinUiStateMachineImpl(
  val partnershipsTransferUiStateMachine: PartnershipsTransferUiStateMachine,
  val partnershipsPurchaseUiStateMachine: PartnershipsPurchaseUiStateMachine,
) : AddBitcoinUiStateMachine {
  @Composable
  override fun model(props: AddBitcoinUiProps): SheetModel {
    var uiState: AddBitcoinUiState by remember {
      mutableStateOf(
        when (props.initialState) {
          AddBitcoinBottomSheetDisplayState.ShowingPurchaseOrTransferUiState -> ShowingBuyOrTransferUiState
          AddBitcoinBottomSheetDisplayState.TransferringUiState -> TransferringUiState
          is AddBitcoinBottomSheetDisplayState.PurchasingUiState -> PurchasingUiState(props.initialState.selectedAmount)
        }
      )
    }
    val showBuyOrTransferState: () -> Unit = {
      uiState = ShowingBuyOrTransferUiState
    }
    return when (val currentState = uiState) {
      ShowingBuyOrTransferUiState ->
        BuyOrTransferModel(
          onPurchase = {
            uiState = PurchasingUiState(selectedAmount = null)
          },
          onTransfer = {
            uiState = TransferringUiState
          },
          onBack = props.onExit
        )

      TransferringUiState ->
        partnershipsTransferUiStateMachine.model(
          props =
            PartnershipsTransferUiProps(
              account = props.account,
              keybox = props.keybox,
              sellBitcoinEnabled = props.sellBitcoinEnabled,
              onBack = {
                if (props.sellBitcoinEnabled) {
                  props.onExit()
                } else {
                  uiState = ShowingBuyOrTransferUiState
                }
              },
              onAnotherWalletOrExchange = props.onAnotherWalletOrExchange,
              onPartnerRedirected = props.onPartnerRedirected,
              onExit = props.onExit
            )
        )

      is PurchasingUiState ->
        partnershipsPurchaseUiStateMachine.model(
          props = PartnershipsPurchaseUiProps(
            selectedAmount = currentState.selectedAmount,
            onPartnerRedirected = props.onPartnerRedirected,
            onBack = showBuyOrTransferState,
            onSelectCustomAmount = props.onSelectCustomAmount,
            onExit = props.onExit
          )
        )
    }
  }
}

private sealed interface AddBitcoinUiState {
  data object ShowingBuyOrTransferUiState : AddBitcoinUiState

  data object TransferringUiState : AddBitcoinUiState

  data class PurchasingUiState(val selectedAmount: FiatMoney?) : AddBitcoinUiState
}
