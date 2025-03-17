package build.wallet.ui.app.platform.permissions

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import build.wallet.statemachine.core.Icon
import build.wallet.statemachine.core.form.FormHeaderModel
import build.wallet.statemachine.platform.permissions.AskingToGoToSystemBodyModel
import build.wallet.ui.app.core.form.FormScreen
import build.wallet.ui.components.button.Button
import build.wallet.ui.components.header.Header
import build.wallet.ui.components.toolbar.Toolbar
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel.Size.Footer
import build.wallet.ui.model.button.ButtonModel.Treatment.Primary
import build.wallet.ui.model.toolbar.ToolbarAccessoryModel.IconAccessory.Companion.CloseAccessory
import build.wallet.ui.model.toolbar.ToolbarModel

@Composable
fun AskingToGoToSystemScreen(
  modifier: Modifier = Modifier,
  model: AskingToGoToSystemBodyModel,
) {
  FormScreen(
    modifier = modifier,
    onBack = model.onBack,
    toolbarContent = {
      Toolbar(
        model =
          ToolbarModel(
            leadingAccessory = CloseAccessory(onClick = model.onBack)
          )
      )
    },
    headerContent = {
      Header(
        model = FormHeaderModel(
          headline = model.title,
          subline = model.explanation,
          icon = Icon.LargeIconWarningFilled
        )
      )
    },
    footerContent = {
      Button(
        text = "Go to System Settings",
        treatment = Primary,
        size = Footer,
        onClick = StandardClick(model.onGoToSetting)
      )
    }
  )
}
