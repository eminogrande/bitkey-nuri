package build.wallet.statemachine.platform.permissions

import androidx.compose.runtime.*
import build.wallet.analytics.events.EventTracker
import build.wallet.analytics.events.EventTrackerContext
import build.wallet.analytics.events.screen.id.NotificationsEventTrackerScreenId
import build.wallet.analytics.v1.Action.ACTION_APP_PUSH_NOTIFICATIONS_DISABLED
import build.wallet.analytics.v1.Action.ACTION_APP_PUSH_NOTIFICATIONS_ENABLED
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.platform.permissions.Permission.PushNotifications
import build.wallet.platform.permissions.PermissionChecker
import build.wallet.platform.permissions.PermissionStatus.Denied
import build.wallet.statemachine.core.BodyModel
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.form.FormHeaderModel
import build.wallet.statemachine.platform.permissions.EnableNotificationsUiStateMachineImpl.UiState.*
import build.wallet.statemachine.platform.permissions.NotificationRationale.Generic
import build.wallet.statemachine.platform.permissions.NotificationRationale.Recovery
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel
import build.wallet.ui.model.button.ButtonModel.Size.Footer
import build.wallet.ui.model.toolbar.ToolbarAccessoryModel
import build.wallet.ui.model.toolbar.ToolbarModel
import platform.Foundation.NSURL
import platform.UIKit.UIApplication
import platform.UIKit.UIApplicationOpenSettingsURLString

private const val ENABLE_STRING = "Enable"

@BitkeyInject(AppScope::class)
class EnableNotificationsUiStateMachineImpl(
  private val notificationPermissionRequester: NotificationPermissionRequester,
  private val permissionChecker: PermissionChecker,
  private val eventTracker: EventTracker,
) : EnableNotificationsUiStateMachine {
  @Composable
  override fun model(props: EnableNotificationsUiProps): BodyModel {
    var uiState: UiState by remember { mutableStateOf(LoadingUiState) }

    when (uiState) {
      LoadingUiState -> {
        uiState =
          when (permissionChecker.getPermissionStatus(PushNotifications)) {
            // this will only be for IOS
            Denied -> OpenSettingsUiState
            else -> EnableNotificationsUiState
          }
      }

      is ShowingSystemPermissionsUiState -> {
        notificationPermissionRequester.requestNotificationPermission(
          onGranted = {
            eventTracker.track(ACTION_APP_PUSH_NOTIFICATIONS_ENABLED)
            props.onComplete()
          },
          onDeclined = {
            eventTracker.track(ACTION_APP_PUSH_NOTIFICATIONS_DISABLED)
            props.onComplete()
          }
        )
      }

      else -> {}
    }

    val sublineMessage = when (props.rationale) {
      Generic -> "Keep your wallet secure and stay updated."
      Recovery -> "You'll be notified with any updates to the status of your Bitkey recovery."
    }
    val subline = if (uiState == OpenSettingsUiState) {
      val sublineSuffix =
        "Open your settings to change notification permissions for the Bitkey app."
      "$sublineMessage $sublineSuffix"
    } else {
      sublineMessage
    }

    return EnableNotificationsBodyModel(
      eventTrackerContext = props.eventTrackerContext,
      onBack = props.retreat.onRetreat,
      subline = subline,
      leadingToolbarAccessory = props.retreat.leadingToolbarAccessory,
      primaryButton =
        when (uiState) {
          LoadingUiState ->
            ButtonModel(
              text = "",
              isEnabled = false,
              isLoading = true,
              size = Footer,
              onClick = StandardClick {} // cannot click when `loading`
            )

          is ShowingSystemPermissionsUiState -> {
            ButtonModel(
              text = ENABLE_STRING,
              isEnabled = false,
              isLoading = false,
              size = Footer,
              onClick = StandardClick {} // cannot click when disabled
            )
          }

          is EnableNotificationsUiState -> {
            ButtonModel(
              text = ENABLE_STRING,
              isEnabled = true,
              isLoading = false,
              size = Footer,
              onClick =
                StandardClick {
                  uiState = ShowingSystemPermissionsUiState
                }
            )
          }

          is OpenSettingsUiState -> {
            ButtonModel(
              text = "Open settings",
              isEnabled = true,
              isLoading = false,
              size = Footer,
              onClick =
                StandardClick {
                  NSURL.URLWithString(UIApplicationOpenSettingsURLString)?.let { settingsURL ->
                    UIApplication.sharedApplication.openURL(settingsURL)
                  }
                }
            )
          }
        }
    )
  }

  private sealed interface UiState {
    /** Indicates the button is loading */
    data object LoadingUiState : UiState

    /** Indicates the button will be used to Enable Notifications */
    data object EnableNotificationsUiState : UiState

    /** Indicates the button will be used to open IOS settings */
    data object OpenSettingsUiState : UiState

    /**
     * When the systems permissions alert is on the button is disabled
     * `showingSystemPermission` is true
     */
    data object ShowingSystemPermissionsUiState : UiState
  }
}

private data class EnableNotificationsBodyModel(
  override val eventTrackerContext: EventTrackerContext,
  override val onBack: () -> Unit,
  override val primaryButton: ButtonModel,
  val leadingToolbarAccessory: ToolbarAccessoryModel,
  val subline: String,
) : FormBodyModel(
    id = NotificationsEventTrackerScreenId.ENABLE_PUSH_NOTIFICATIONS,
    eventTrackerContext = eventTrackerContext,
    onBack = onBack,
    toolbar = ToolbarModel(leadingAccessory = leadingToolbarAccessory),
    header =
      FormHeaderModel(
        headline = "Enable Push Notifications on this Phone.",
        subline = subline
      ),
    primaryButton = primaryButton
  )
