package build.wallet.ui.app.nfc

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize.Min
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Alignment.Companion.CenterHorizontally
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import bitkey.ui.framework_public.generated.resources.Res
import build.wallet.statemachine.nfc.FwupInstructionsBodyModel
import build.wallet.ui.components.button.Button
import build.wallet.ui.components.header.Header
import build.wallet.ui.components.label.LabelTreatment.Primary
import build.wallet.ui.components.toolbar.Toolbar
import build.wallet.ui.components.video.VideoPlayer
import build.wallet.ui.compose.getVideoResource
import build.wallet.ui.system.BackHandler
import build.wallet.ui.theme.WalletTheme

@Composable
fun FwupInstructionsScreen(
  modifier: Modifier = Modifier,
  model: FwupInstructionsBodyModel,
) {
  BackHandler(onBack = model.onBack)
  Box(
    modifier = modifier
      .fillMaxSize()
      .background(Color.Black)
  ) {
    BoxWithConstraints {
      VideoPlayer(
        modifier =
          Modifier
            .wrapContentSize(Alignment.TopCenter, unbounded = true)
            .size(maxWidth + 200.dp),
        resourcePath = Res.getVideoResource("pair"),
        isLooping = false
      )
    }

    Column(
      modifier = Modifier.statusBarsPadding(),
      horizontalAlignment = CenterHorizontally
    ) {
      Toolbar(
        modifier = Modifier.padding(horizontal = 20.dp),
        model = model.toolbarModel
      )
      Spacer(Modifier.weight(1F))
      Column(
        modifier =
          Modifier
            .height(Min)
            .clip(RoundedCornerShape(24.dp, 24.dp, 0.dp, 0.dp))
            .background(WalletTheme.colors.background)
            .padding(horizontal = 20.dp)
      ) {
        Spacer(Modifier.height(16.dp))
        Header(
          model = model.headerModel,
          sublineLabelTreatment = Primary
        )
        Spacer(Modifier.height(24.dp))
        Button(
          model = model.buttonModel
        )
        Spacer(Modifier.height(28.dp))
      }
    }
  }
}
