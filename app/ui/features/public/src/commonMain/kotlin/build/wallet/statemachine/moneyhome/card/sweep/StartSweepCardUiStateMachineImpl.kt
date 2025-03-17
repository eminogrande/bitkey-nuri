package build.wallet.statemachine.moneyhome.card.sweep

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import build.wallet.di.ActivityScope
import build.wallet.di.BitkeyInject
import build.wallet.recovery.sweep.SweepService
import build.wallet.statemachine.core.Icon
import build.wallet.statemachine.core.LabelModel
import build.wallet.statemachine.moneyhome.card.CardModel
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel
import build.wallet.ui.model.button.ButtonModel.Treatment.Warning

@BitkeyInject(ActivityScope::class)
class StartSweepCardUiStateMachineImpl(
  private val sweepService: SweepService,
) : StartSweepCardUiStateMachine {
  @Composable
  override fun model(props: StartSweepCardUiProps): CardModel? {
    val sweepRequiredState by sweepService.sweepRequired.collectAsState()

    return when (sweepRequiredState) {
      false -> null
      true -> CardModel(
        title = LabelModel.StringWithStyledSubstringModel.from("Funds in inactive wallet", emptyMap()),
        subtitle = "Transfer funds now",
        leadingImage = CardModel.CardImage.StaticImage(
          icon = Icon.SmallIconInformationFilled,
          iconTint = CardModel.CardImage.StaticImage.IconTint.Warning
        ),
        content = null,
        style = CardModel.CardStyle.Gradient(backgroundColor = CardModel.CardStyle.Gradient.BackgroundColor.Default),
        onClick = props.onStartSweepClicked,
        trailingButton = ButtonModel(
          text = "->",
          size = ButtonModel.Size.Compact,
          treatment = Warning,
          onClick = StandardClick(props.onStartSweepClicked)
        )
      )
    }
  }
}
