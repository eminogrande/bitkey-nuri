package build.wallet.ui.app.dev.analytics

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import build.wallet.statemachine.dev.analytics.AnalyticsBodyModel
import build.wallet.ui.components.button.Button
import build.wallet.ui.components.card.Card
import build.wallet.ui.components.layout.Divider
import build.wallet.ui.components.list.ListItem
import build.wallet.ui.components.toolbar.Toolbar
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel.Size
import build.wallet.ui.model.button.ButtonModel.Treatment.TertiaryDestructive
import build.wallet.ui.model.list.ListItemAccessory
import build.wallet.ui.model.list.ListItemModel
import build.wallet.ui.model.switch.SwitchModel
import build.wallet.ui.model.toolbar.ToolbarAccessoryModel.IconAccessory.Companion.BackAccessory
import build.wallet.ui.model.toolbar.ToolbarMiddleAccessoryModel
import build.wallet.ui.model.toolbar.ToolbarModel
import build.wallet.ui.system.BackHandler
import kotlinx.collections.immutable.ImmutableList

@Composable
fun AnalyticsScreen(
  modifier: Modifier = Modifier,
  model: AnalyticsBodyModel,
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
          middleAccessory = ToolbarMiddleAccessoryModel(title = "Analytics")
        )
    )
    Spacer(Modifier.height(24.dp))
    Card {
      ListItem(
        title = "Enable analytics",
        secondaryText = "This controls whether analytics are tracked. This is always enabled in customer builds",
        trailingAccessory = ListItemAccessory.SwitchAccessory(
          model = SwitchModel(
            checked = model.isEnabled,
            onCheckedChange = model.onEnableChanged
          )
        )
      )
    }
    Spacer(Modifier.height(24.dp))
    Card {
      Button(
        text = "Clear events",
        treatment = TertiaryDestructive,
        size = Size.Footer,
        onClick = StandardClick(model.onClear)
      )
    }
    Spacer(Modifier.height(24.dp))
    EventsCard(model.events)
  }
}

@Composable
private fun EventsCard(events: ImmutableList<ListItemModel>) {
  Card {
    LazyColumn {
      items(events) {
        ListItem(model = it)
        Divider()
      }
    }
  }
}
