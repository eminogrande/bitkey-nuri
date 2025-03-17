package build.wallet.ui.app.dev

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import build.wallet.statemachine.dev.FirmwareMetadataBodyModel
import build.wallet.ui.components.button.Button
import build.wallet.ui.components.card.Card
import build.wallet.ui.components.layout.Divider
import build.wallet.ui.components.list.ListItem
import build.wallet.ui.components.toolbar.Toolbar
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel.Companion.BitkeyInteractionButtonModel
import build.wallet.ui.model.button.ButtonModel.Size.Footer
import build.wallet.ui.model.toolbar.ToolbarAccessoryModel.IconAccessory.Companion.BackAccessory
import build.wallet.ui.model.toolbar.ToolbarMiddleAccessoryModel
import build.wallet.ui.model.toolbar.ToolbarModel
import build.wallet.ui.system.BackHandler
import build.wallet.ui.theme.WalletTheme

@Composable
fun FirmwareMetadataScreen(
  modifier: Modifier = Modifier,
  model: FirmwareMetadataBodyModel,
) {
  BackHandler(onBack = model.onBack)

  Column(
    modifier = modifier
      .background(WalletTheme.colors.background)
      .fillMaxSize()
      .padding(horizontal = 20.dp)
  ) {
    Toolbar(
      model =
        ToolbarModel(
          leadingAccessory = BackAccessory(onClick = model.onBack),
          middleAccessory = ToolbarMiddleAccessoryModel(title = "Firmware Metadata")
        )
    )

    Spacer(Modifier.height(24.dp))
    Button(
      model = BitkeyInteractionButtonModel(
        text = "Refresh Metadata",
        size = Footer,
        onClick = StandardClick(model.onFirmwareMetadataRefreshClick)
      )
    )

    model.firmwareMetadataModel?.let { metadata ->
      Spacer(Modifier.height(24.dp))
      Card {
        ListItem(
          title = "Active Slot",
          sideText = metadata.activeSlot
        )

        Divider()
        ListItem(
          title = "Git ID",
          sideText = metadata.gitId
        )

        Divider()
        ListItem(
          title = "Git Branch",
          sideText = metadata.gitBranch
        )

        Divider()
        ListItem(
          title = "Version",
          sideText = metadata.version
        )

        Divider()
        ListItem(
          title = "Build",
          sideText = metadata.build
        )

        Divider()
        ListItem(
          title = "Timestamp",
          sideText = metadata.timestamp
        )

        Divider()
        ListItem(
          title = "Hash",
          sideText = metadata.hash
        )

        Divider()
        ListItem(
          title = "HW Revision",
          sideText = metadata.hwRevision
        )
      }
    }
  }
}
