package build.wallet.ui.data

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import build.wallet.statemachine.core.form.FormMainContentModel
import build.wallet.ui.components.label.Label
import build.wallet.ui.components.label.LabelTreatment.Secondary
import build.wallet.ui.tokens.LabelType

@Composable
internal fun DataRowTotal(
  modifier: Modifier = Modifier,
  model: FormMainContentModel.DataList.Data,
) {
  DataRowTotal(
    modifier = modifier,
    leadingContent = {
      Column {
        Label(
          text = model.title,
          type = LabelType.Body2Bold,
          alignment = TextAlign.Start
        )
        model.secondaryTitle?.let { secondaryTitle ->
          Label(
            text = secondaryTitle,
            type = LabelType.Body3Regular,
            alignment = TextAlign.Start,
            treatment = Secondary
          )
        }
      }
    },
    trailingContent = {
      Column(
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.End
      ) {
        Label(
          text = model.sideText,
          type = LabelType.Body2Bold,
          alignment = TextAlign.End
        )
        model.secondarySideText?.let { secondarySideText ->
          Label(
            text = secondarySideText,
            type = LabelType.Body3Regular,
            alignment = TextAlign.End,
            treatment = Secondary
          )
        }
      }
    }
  )
}

@Composable
private fun DataRowTotal(
  modifier: Modifier = Modifier,
  leadingContent: @Composable () -> Unit,
  trailingContent: @Composable () -> Unit,
) {
  Row(
    modifier =
      modifier
        .fillMaxWidth()
        .padding(top = 12.dp, bottom = 14.dp),
    verticalAlignment = Alignment.CenterVertically,
    horizontalArrangement = Arrangement.SpaceBetween
  ) {
    leadingContent()
    Spacer(Modifier.width(16.dp))
    trailingContent()
  }
}
