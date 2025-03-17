package build.wallet.ui.compose.gestures

import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.input.pointer.*
import androidx.compose.ui.util.fastForEach
import build.wallet.ui.compose.gestures.State.*
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * Configure component to receive two finger double tap events within a short enough period of time.
 *
 * @param block - gets executed on two finger double tap.
 */
fun Modifier.onTwoFingerDoubleTap(block: () -> Unit) =
  then(
    composed {
      var state: State by remember { mutableStateOf(WaitingForFirstTwoFingerTap) }

      when (val s = state) {
        is FirstAndSecondDoubleTap -> {
          LaunchedEffect("evaluate last two events $state") {
            // See if two most recent two finger taps happened within a short enough time period.
            if (s.second - s.first < doubleTapTimeout) {
              block()
              // Reset state.
              state = WaitingForFirstTwoFingerTap
            }
          }
        }

        else -> {}
      }

      Modifier.pointerInput(block) {
        awaitEachGesture {
          awaitTwoDowns()
          val now = Clock.System.now()
          state =
            when (val s = state) {
              is WaitingForFirstTwoFingerTap -> WaitingForSecondTwoFingerTap(now)
              is WaitingForSecondTwoFingerTap -> FirstAndSecondDoubleTap(first = s.first, second = now)
              is FirstAndSecondDoubleTap -> FirstAndSecondDoubleTap(first = s.second, second = now)
              else -> s
            }
        }
      }
    }
  )

/** Duration window within which two finger events (last two) should happen. */
private val doubleTapTimeout: Duration = 300.milliseconds

/**
 * State for two finger double tap action.
 */
private sealed class State {
  /** Indicates that we are waiting for the first two finger tap */
  data object WaitingForFirstTwoFingerTap : State()

  /**
   * Indicates that we have the first two finger tap, waiting for the second one.
   *
   * @property first - timestamp for the first two finger tap event.
   */
  data class WaitingForSecondTwoFingerTap(
    val first: Instant,
  ) : State()

  /**
   * Indicates that we have the first two finger tap, waiting for the second one.
   *
   * @property first - timestamp for the first two finger tap event.
   */
  data class WaitingForThirdTwoFingerTap(
    val first: Instant,
    val second: Instant,
  ) : State()

  /**
   * Indicates that we have two most recent double tap events.
   *
   * @property first - timestamp for the first two finger tap event.
   * @property second - timestamp for the first two finger tap event.
   */
  data class FirstAndSecondDoubleTap(
    val first: Instant,
    val second: Instant,
  ) : State()

  /**
   * Indicates that we have two most recent double tap events.
   *
   * @property first - timestamp for the first two finger tap event.
   * @property second - timestamp for the second two finger tap event.
   * @property third - timestamp for the third two finger tap event.
   */
  data class FirstSecondAndThirdDoubleTap(
    val first: Instant,
    val second: Instant,
    val third: Instant,
  ) : State()
}

/**
 * Suspend until two down pointer events are reported.
 */
private suspend fun AwaitPointerEventScope.awaitTwoDowns(requireUnconsumed: Boolean = true) {
  var event: PointerEvent
  var firstDown: PointerId? = null
  do {
    event = awaitPointerEvent()
    var downPointers = if (firstDown != null) 1 else 0
    event.changes.fastForEach {
      val isDown =
        if (requireUnconsumed) it.changedToDown() else it.changedToDownIgnoreConsumed()
      val isUp =
        if (requireUnconsumed) it.changedToUp() else it.changedToUpIgnoreConsumed()
      if (isUp && firstDown == it.id) {
        firstDown = null
        downPointers -= 1
      }
      if (isDown) {
        firstDown = it.id
        downPointers += 1
      }
    }
    val satisfied = downPointers > 1
  } while (!satisfied)
}
