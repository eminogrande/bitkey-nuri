package build.wallet.ui.app.dev.logs

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import build.wallet.statemachine.dev.logs.LogRowModel
import build.wallet.statemachine.dev.logs.LogsBodyModel
import build.wallet.statemachine.dev.logs.LogsModel
import build.wallet.ui.components.button.Button
import build.wallet.ui.components.card.Card
import build.wallet.ui.components.layout.Divider
import build.wallet.ui.components.list.ListItem
import build.wallet.ui.components.toolbar.Toolbar
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel.Size
import build.wallet.ui.model.button.ButtonModel.Treatment.TertiaryDestructive
import build.wallet.ui.model.list.ListItemAccessory.SwitchAccessory
import build.wallet.ui.model.switch.SwitchModel
import build.wallet.ui.model.toolbar.ToolbarAccessoryModel.IconAccessory.Companion.BackAccessory
import build.wallet.ui.model.toolbar.ToolbarMiddleAccessoryModel
import build.wallet.ui.model.toolbar.ToolbarModel
import build.wallet.ui.system.BackHandler
import build.wallet.ui.theme.WalletTheme

@Composable
fun LogsScreen(
  modifier: Modifier = Modifier,
  model: LogsBodyModel,
) {
  BackHandler(onBack = model.onBack)
  Column(
    modifier = modifier
      .padding(horizontal = 20.dp)
      .fillMaxSize(),
    horizontalAlignment = Alignment.CenterHorizontally
  ) {
    Toolbar(
      model =
        ToolbarModel(
          leadingAccessory = BackAccessory(onClick = model.onBack),
          middleAccessory = ToolbarMiddleAccessoryModel(title = "Logs")
        )
    )
    Spacer(Modifier.height(24.dp))
    Card {
      ListItem(
        title = "Errors only",
        trailingAccessory =
          SwitchAccessory(
            model =
              SwitchModel(
                checked = model.errorsOnly,
                onCheckedChange = model.onErrorsOnlyValueChanged
              )
          )
      )
      ListItem(
        title = "Analytics only",
        trailingAccessory =
          SwitchAccessory(
            model =
              SwitchModel(
                checked = model.analyticsEventsOnly,
                onCheckedChange = model.onAnalyticsEventsOnlyValueChanged
              )
          )
      )
      Divider()
      Button(
        text = "Clear logs",
        treatment = TertiaryDestructive,
        size = Size.Footer,
        onClick = StandardClick(model.onClear)
      )
    }
    Spacer(Modifier.height(24.dp))
    LogsCard(model.logsModel)
  }
}

@Composable
private fun LogsCard(model: LogsModel) {
  Card {
    LazyColumn {
      items(model.logRows) {
        LogRow(model = it)
        Divider()
      }
    }
  }
}

@Composable
private fun LogRow(model: LogRowModel) {
  val backgroundColor =
    when (model.isError) {
      true -> WalletTheme.colors.destructive.copy(alpha = 0.05f)
      else -> WalletTheme.colors.background
    }
  val throwable = model.throwableDescription?.let { "\n\n$it" }.orEmpty()
  val message = "${model.message}$throwable"
  ListItem(
    modifier =
      Modifier
        .fillMaxWidth()
        .background(color = backgroundColor),
    title = model.dateTime,
    secondaryText = "${model.level} ${model.tag}\n\n$message"
  )
}
