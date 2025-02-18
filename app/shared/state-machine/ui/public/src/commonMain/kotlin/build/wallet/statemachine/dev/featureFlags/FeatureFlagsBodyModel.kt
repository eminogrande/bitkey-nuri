package build.wallet.statemachine.dev.featureFlags

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import build.wallet.analytics.events.screen.EventTrackerScreenInfo
import build.wallet.statemachine.core.BodyModel
import build.wallet.ui.app.dev.flags.FeatureFlagsScreen
import build.wallet.ui.model.list.ListGroupModel

/**
 * Model for showing screen with feature flags.
 */
data class FeatureFlagsBodyModel(
  val flagsModel: ListGroupModel,
  override val onBack: () -> Unit,
  val onReset: () -> Unit,
  // This is only used by the debug menu, it doesn't need a screen ID
  override val eventTrackerScreenInfo: EventTrackerScreenInfo? = null,
) : BodyModel() {
  @Composable
  override fun render(modifier: Modifier) {
    FeatureFlagsScreen(modifier, model = this)
  }
}
