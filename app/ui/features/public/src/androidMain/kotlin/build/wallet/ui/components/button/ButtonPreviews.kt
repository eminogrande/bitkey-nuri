@file:Suppress("TooManyFunctions")

package build.wallet.ui.components.button

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import build.wallet.statemachine.core.Icon
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel
import build.wallet.ui.model.button.ButtonModel.Size.*
import build.wallet.ui.model.button.ButtonModel.Treatment.Tertiary
import build.wallet.ui.tooling.PreviewWalletTheme
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.seconds

@Preview
@Composable
fun RegularButtonsWithIconEnabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Regular,
      showLeadingIcon = true,
      enabled = true
    )
  }
}

@Preview
@Composable
fun RegularButtonsWithIconDisabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Regular,
      showLeadingIcon = true,
      enabled = false
    )
  }
}

@Preview
@Composable
fun RegularButtonsWithoutIconEnabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Regular,
      showLeadingIcon = false,
      enabled = true
    )
  }
}

@Preview
@Composable
fun RegularButtonsWithoutIconDisabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Regular,
      showLeadingIcon = false,
      enabled = false
    )
  }
}

@Preview
@Composable
fun CompactButtonsWithIconEnabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Compact,
      showLeadingIcon = true,
      enabled = true
    )
  }
}

@Preview
@Composable
fun CompactButtonsWithIconDisabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Compact,
      showLeadingIcon = true,
      enabled = false
    )
  }
}

@Preview
@Composable
fun CompactButtonsWithoutIconEnabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Compact,
      showLeadingIcon = false,
      enabled = true
    )
  }
}

@Preview
@Composable
fun CompactButtonsWithoutIconDisabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Compact,
      showLeadingIcon = false,
      enabled = false
    )
  }
}

@Preview
@Composable
fun FooterButtonsWithIconEnabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Footer,
      showLeadingIcon = true,
      enabled = true
    )
  }
}

@Preview
@Composable
fun FooterButtonsWithIconDisabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Footer,
      showLeadingIcon = true,
      enabled = false
    )
  }
}

@Preview
@Composable
fun FooterButtonsWithoutIconEnabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Footer,
      showLeadingIcon = false,
      enabled = true
    )
  }
}

@Preview
@Composable
fun FooterButtonsWithoutIconDisabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Footer,
      showLeadingIcon = false,
      enabled = false
    )
  }
}

@Preview
@Composable
fun ElevatedRegularButtonsEnabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Regular,
      showLeadingIcon = false,
      enabled = true
    )
  }
}

@Preview
@Composable
fun ElevatedRegularButtonsDisabled() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Regular,
      showLeadingIcon = false,
      enabled = false
    )
  }
}

@Preview
@Composable
fun RegularButtonLoading() {
  PreviewWalletTheme {
    AllButtonsForSizeAndIcon(
      size = Regular,
      showLeadingIcon = false,
      isLoading = true,
      enabled = true
    )
  }
}

@Composable
private fun AllButtonsForSizeAndIcon(
  size: ButtonModel.Size,
  showLeadingIcon: Boolean,
  enabled: Boolean,
  isLoading: Boolean = false,
) {
  Box(
    modifier =
      Modifier
        .fillMaxWidth()
        .padding(
          horizontal = 20.dp,
          vertical = 5.dp
        ),
    contentAlignment = Alignment.Center
  ) {
    Column(
      verticalArrangement = Arrangement.spacedBy(10.dp),
      horizontalAlignment = Alignment.CenterHorizontally
    ) {
      ButtonModel.Treatment.entries.forEach { treatment ->
        Button(
          text = treatment.name.readable(),
          treatment = treatment,
          isLoading = isLoading,
          leadingIcon = if (showLeadingIcon) Icon.SmallIconBitkey else null,
          size = size,
          enabled = enabled,
          onClick = StandardClick {}
        )
      }
    }
  }
}

@Preview
@Composable
private fun ButtonLoadingPreview() {
  var isLoading by remember { mutableStateOf(false) }
  LaunchedEffect(isLoading) {
    delay(2.seconds)
    isLoading = !isLoading
  }

  PreviewWalletTheme {
    Box(modifier = Modifier.padding(5.dp)) {
      Button(
        text = "Hello Bitcoin!",
        treatment = ButtonModel.Treatment.Primary,
        isLoading = isLoading,
        size = Regular,
        onClick = StandardClick {}
      )
    }
  }
}

@Preview
@Composable
private fun ButtonWithLongTextPreview() {
  PreviewWalletTheme {
    Box(
      modifier = Modifier
        .padding(5.dp)
        .height(72.dp)
    ) {
      Button(
        text = "Your information will be collected and used in accordance with our Privacy Notice",
        treatment = Tertiary,
        size = FitContent,
        onClick = StandardClick { }
      )
    }
  }
}

private fun String.readable(): String {
  // Insert space before uppercase letters and convert the string to lowercase
  val withSpaces = this.replace("(?<!^)(?=[A-Z])".toRegex(), " ").lowercase()
  // Capitalize the first character of the resulting string
  return withSpaces.replaceFirstChar {
    if (it.isLowerCase()) it.titlecase() else it.toString()
  }
}
