package build.wallet.statemachine.settings

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import build.wallet.analytics.events.screen.EventTrackerScreenInfo
import build.wallet.analytics.events.screen.id.SettingsEventTrackerScreenId
import build.wallet.statemachine.core.BodyModel
import build.wallet.statemachine.core.Icon
import build.wallet.ui.app.settings.SettingsScreen
import build.wallet.ui.model.icon.IconModel
import build.wallet.ui.model.toolbar.ToolbarAccessoryModel.IconAccessory.Companion.BackAccessory
import build.wallet.ui.model.toolbar.ToolbarMiddleAccessoryModel
import build.wallet.ui.model.toolbar.ToolbarModel
import kotlinx.collections.immutable.ImmutableList

data class SettingsBodyModel(
  override val onBack: () -> Unit,
  val toolbarModel: ToolbarModel,
  val sectionModels: ImmutableList<SectionModel>,
  override val eventTrackerScreenInfo: EventTrackerScreenInfo? =
    EventTrackerScreenInfo(
      eventTrackerScreenId = SettingsEventTrackerScreenId.SETTINGS
    ),
) : BodyModel() {
  data class SectionModel(
    val sectionHeaderTitle: String,
    val rowModels: ImmutableList<RowModel>,
  )

  data class RowModel(
    val icon: Icon,
    val title: String,
    val isDisabled: Boolean,
    val specialTrailingIconModel: IconModel? = null,
    val showNewCoachmark: Boolean = false,
    val onClick: () -> Unit,
  )

  constructor(
    onBack: () -> Unit,
    sectionModels: ImmutableList<SectionModel>,
  ) : this(
    onBack = onBack,
    toolbarModel = ToolbarModel(
      leadingAccessory = BackAccessory(onClick = onBack),
      middleAccessory = ToolbarMiddleAccessoryModel(title = "Settings")
    ),
    sectionModels = sectionModels
  )

  @Composable
  override fun render(modifier: Modifier) {
    SettingsScreen(modifier, model = this)
  }
}
