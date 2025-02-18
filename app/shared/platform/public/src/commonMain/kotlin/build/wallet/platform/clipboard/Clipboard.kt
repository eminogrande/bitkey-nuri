package build.wallet.platform.clipboard

import build.wallet.coroutines.flow.tickerFlow
import build.wallet.platform.clipboard.ClipItem.PlainText
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlin.time.Duration.Companion.seconds

/**
 * Interface to platform's clipboard service, for placing text in the global clipboard.
 */
interface Clipboard {
  /**
   * Sets the primary clipboard item in the global clipboard.
   *
   * On Android, this sets primary clip [item].
   * On iOS, this clear all existing clipboard items before setting [item], as per [UIPasteboard].
   */
  fun setItem(item: ClipItem)

  /**
   * Retrieves text last copied by the user in their clipboard.
   *
   * If a plain text does not exist inside the user's clipboard, then we will return nil.
   */
  fun getPlainTextItem(): PlainText?

  /**
   * Retrieves text last copied by the user in their clipboard, but ONLY on Android.
   *
   * If a plain text does not exist inside the user's clipboard, then we will return nil.
   */
  fun getPlainTextItemAndroid(): PlainText?
}

fun Clipboard.plainTextItem(): Flow<PlainText?> {
  return tickerFlow(1.seconds)
    .map { getPlainTextItem() }
    .distinctUntilChanged()
}

fun Clipboard.plainTextItemAndroid(): Flow<PlainText?> {
  return tickerFlow(1.seconds)
    .map { getPlainTextItemAndroid() }
    .distinctUntilChanged()
}
