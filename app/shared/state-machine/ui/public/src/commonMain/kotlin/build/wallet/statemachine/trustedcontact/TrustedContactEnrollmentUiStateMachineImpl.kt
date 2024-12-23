package build.wallet.statemachine.trustedcontact

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import build.wallet.analytics.events.EventTracker
import build.wallet.analytics.events.screen.id.SocialRecoveryEventTrackerScreenId.*
import build.wallet.analytics.v1.Action
import build.wallet.bitkey.relationships.DelegatedDecryptionKey
import build.wallet.bitkey.relationships.IncomingInvitation
import build.wallet.bitkey.relationships.ProtectedCustomer
import build.wallet.bitkey.relationships.ProtectedCustomerAlias
import build.wallet.crypto.PublicKey
import build.wallet.di.ActivityScope
import build.wallet.di.BitkeyInject
import build.wallet.logging.*
import build.wallet.platform.device.DeviceInfoProvider
import build.wallet.relationships.*
import build.wallet.statemachine.core.LoadingBodyModel
import build.wallet.statemachine.core.Retreat
import build.wallet.statemachine.core.RetreatStyle
import build.wallet.statemachine.core.ScreenModel
import build.wallet.statemachine.trustedcontact.model.*
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess

@BitkeyInject(ActivityScope::class)
class TrustedContactEnrollmentUiStateMachineImpl(
  private val relationshipsKeysRepository: RelationshipsKeysRepository,
  private val deviceInfoProvider: DeviceInfoProvider,
  private val eventTracker: EventTracker,
  private val relationshipsService: RelationshipsService,
) : TrustedContactEnrollmentUiStateMachine {
  @Composable
  override fun model(props: TrustedContactEnrollmentUiProps): ScreenModel {
    var uiState: State by remember {
      if (props.inviteCode != null) {
        eventTracker.track(Action.ACTION_APP_SOCREC_ENTERED_INVITE_VIA_DEEPLINK)
        mutableStateOf(State.RetrievingInviteWithF8e)
      } else {
        mutableStateOf(State.EnteringInviteCode)
      }
    }
    var inviteCode by remember { mutableStateOf(props.inviteCode ?: "") }

    return when (val state = uiState) {
      is State.EnteringInviteCode -> {
        EnteringInviteCodeBodyModel(
          value = inviteCode,
          onValueChange = { inviteCode = it },
          primaryButton =
            ButtonModel(
              text = "Continue",
              isEnabled = inviteCode.isNotEmpty(),
              size = ButtonModel.Size.Footer,
              onClick = StandardClick {
                uiState = State.RetrievingInviteWithF8e
              }
            ),
          retreat = props.retreat
        )
      }

      is State.RetrievingInviteWithF8e -> {
        LaunchedEffect("retrieve-invitation") {
          relationshipsService.retrieveInvitation(props.account, inviteCode)
            .onFailure {
              logWarn(throwable = it.cause) { "Failed to retrieve invite using code [$inviteCode]" }
              uiState =
                State.RetrievingInviteWithF8eFailure(
                  error = it
                )
            }
            .onSuccess {
              uiState = State.EnteringProtectedCustomerName(it)
            }
        }
        LoadingBodyModel(id = TC_ENROLLMENT_RETRIEVE_INVITE_FROM_F8E)
      }

      is State.RetrievingInviteWithF8eFailure ->
        RetrievingInviteWithF8eFailureBodyModel(
          error = state.error,
          onRetry = { uiState = State.RetrievingInviteWithF8e },
          onBack = { uiState = State.EnteringInviteCode }
        )

      is State.EnteringProtectedCustomerName -> {
        var value by remember { mutableStateOf("") }
        EnteringProtectedCustomerNameBodyModel(
          value = value,
          onValueChange = { value = it },
          primaryButton =
            ButtonModel(
              text = "Continue",
              isEnabled = value.isNotEmpty(),
              size = ButtonModel.Size.Footer,
              onClick =
                StandardClick {
                  uiState =
                    State.LoadIdentityKey(state.invitation, ProtectedCustomerAlias(value))
                }
            ),
          retreat =
            Retreat(
              style = RetreatStyle.Back,
              onRetreat = { uiState = State.EnteringInviteCode }
            )
        )
      }

      is State.LoadIdentityKey -> {
        LaunchedEffect("load-keys") {
          relationshipsKeysRepository.getOrCreateKey<DelegatedDecryptionKey>()
            .onSuccess { key ->
              uiState = State.AcceptingInviteWithF8e(state.invitation, state.protectedCustomerAlias, key)
            }
            .onFailure {
              uiState = State.LoadIdentityKeyFailure(state.invitation, state.protectedCustomerAlias, it)
            }
        }
        LoadingBodyModel(id = TC_ENROLLMENT_LOAD_KEY)
      }

      is State.LoadIdentityKeyFailure ->
        LoadKeyFailureBodyModel(
          onBack = { uiState = State.EnteringProtectedCustomerName(state.invitation) },
          onRetry = { uiState = State.LoadIdentityKey(state.invitation, state.protectedCustomerAlias) }
        )

      is State.AcceptingInviteWithF8e -> {
        LaunchedEffect("accept-invitation") {
          relationshipsService.acceptInvitation(
            account = props.account,
            invitation = state.invitation,
            protectedCustomerAlias = state.protectedCustomerAlias,
            delegatedDecryptionKey = state.delegatedDecryptionKey,
            inviteCode = inviteCode
          ).onFailure {
            uiState =
              State.AcceptingInviteWithF8eFailure(
                error = it,
                invitation = state.invitation,
                protectedCustomerAlias = state.protectedCustomerAlias,
                delegatedDecryptionKey = state.delegatedDecryptionKey
              )
          }
            .onSuccess {
              uiState = State.AcceptingInviteWithF8eSuccess(it)
            }
        }
        LoadingBodyModel(id = TC_ENROLLMENT_ACCEPT_INVITE_WITH_F8E)
      }

      is State.AcceptingInviteWithF8eFailure ->
        AcceptingInviteWithF8eFailureBodyModel(
          error = state.error,
          onRetry = {
            uiState = State.AcceptingInviteWithF8e(state.invitation, state.protectedCustomerAlias, state.delegatedDecryptionKey)
          },
          devicePlatform = deviceInfoProvider.getDeviceInfo().devicePlatform,
          onBack = { uiState = State.EnteringProtectedCustomerName(state.invitation) }
        )

      is State.AcceptingInviteWithF8eSuccess -> {
        AcceptingInviteWithF8eSuccessBodyModel(
          protectedCustomer = state.protectedCustomer,
          onDone = props.onDone
        )
      }
    }.asScreen(props.screenPresentationStyle)
  }
}

private sealed interface State {
  /**
   * The user is entering an invite code.
   * Optional step, omitted if the app is launched from a deeplink with an invite code embedded
   */
  data object EnteringInviteCode : State

  /** Server call to f8e to retrieve the invite data from the code */
  data object RetrievingInviteWithF8e : State

  /** Server call to f8e to retrieve the invite data from the code failed */
  data class RetrievingInviteWithF8eFailure(
    val error: RetrieveInvitationCodeError,
  ) : State

  /** The user is entering the name of the customer they will be protecting */
  data class EnteringProtectedCustomerName(
    val invitation: IncomingInvitation,
  ) : State

  /** Call to load the [DelegatedDecryptionKey] */
  data class LoadIdentityKey(
    val invitation: IncomingInvitation,
    val protectedCustomerAlias: ProtectedCustomerAlias,
  ) : State

  /** Failed to load the [DelegatedDecryptionKey] */
  data class LoadIdentityKeyFailure(
    val invitation: IncomingInvitation,
    val protectedCustomerAlias: ProtectedCustomerAlias,
    val relationshipsKeyError: RelationshipsKeyError,
  ) : State

  /** Server call to f8e to accept the invite */
  data class AcceptingInviteWithF8e(
    val invitation: IncomingInvitation,
    val protectedCustomerAlias: ProtectedCustomerAlias,
    val delegatedDecryptionKey: PublicKey<DelegatedDecryptionKey>,
  ) : State

  /** Server call to f8e to retrieve the invite data from the code failed */
  data class AcceptingInviteWithF8eFailure(
    val error: AcceptInvitationCodeError,
    val invitation: IncomingInvitation,
    val protectedCustomerAlias: ProtectedCustomerAlias,
    val delegatedDecryptionKey: PublicKey<DelegatedDecryptionKey>,
  ) : State

  /** Screen shown when enrolling as a Trusted Contact succeeded, after accepting the invite. */
  data class AcceptingInviteWithF8eSuccess(
    val protectedCustomer: ProtectedCustomer,
  ) : State
}
