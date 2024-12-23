package build.wallet.statemachine.settings.full.feedback

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import build.wallet.bitkey.f8e.AccountId
import build.wallet.di.ActivityScope
import build.wallet.di.BitkeyInject
import build.wallet.f8e.F8eEnvironment
import build.wallet.statemachine.core.ButtonDataModel
import build.wallet.statemachine.core.ErrorFormBodyModel
import build.wallet.statemachine.core.LoadingBodyModel
import build.wallet.statemachine.core.ScreenModel
import build.wallet.support.SupportTicketData
import build.wallet.support.SupportTicketForm
import build.wallet.support.SupportTicketRepository
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess

@BitkeyInject(ActivityScope::class)
class FeedbackUiStateMachineImpl(
  private val supportTicketRepository: SupportTicketRepository,
  private val feedbackFormUiStateMachine: FeedbackFormUiStateMachine,
) : FeedbackUiStateMachine {
  @Composable
  override fun model(props: FeedbackUiProps): ScreenModel {
    var uiState: FeedbackUiState by remember {
      mutableStateOf(FeedbackUiState.LoadingFormStructure)
    }

    return when (val state = uiState) {
      FeedbackUiState.LoadingFormStructure ->
        LoadingFormStructure(
          f8eEnvironment = props.f8eEnvironment,
          accountId = props.accountId,
          onStructureLoaded = { form, initialData ->
            uiState =
              FeedbackUiState.FillingForm(
                initialData = initialData,
                structure = form
              )
          },
          onLoadFailed = {
            uiState = FeedbackUiState.LoadingFormFailed
          }
        )
      FeedbackUiState.LoadingFormFailed ->
        LoadingFormFailed(
          onBack = props.onBack,
          onRetry = {
            uiState = FeedbackUiState.LoadingFormStructure
          }
        )
      is FeedbackUiState.FillingForm ->
        feedbackFormUiStateMachine.model(
          props =
            FeedbackFormUiProps(
              f8eEnvironment = props.f8eEnvironment,
              accountId = props.accountId,
              formStructure = state.structure,
              initialData = state.initialData,
              onBack = props.onBack
            )
        )
    }
  }

  @Composable
  private fun LoadingFormStructure(
    f8eEnvironment: F8eEnvironment,
    accountId: AccountId,
    onStructureLoaded: (form: SupportTicketForm, initialData: SupportTicketData) -> Unit,
    onLoadFailed: () -> Unit,
  ): ScreenModel {
    LaunchedEffect("load-form-structure") {
      supportTicketRepository.loadFormStructure(f8eEnvironment, accountId)
        .onSuccess { value ->
          val initialData = supportTicketRepository.prefillKnownFields(value)
          onStructureLoaded(value, initialData)
        }
        .onFailure { onLoadFailed() }
    }

    return LoadingBodyModel(
      id = FeedbackEventTrackerScreenId.FEEDBACK_LOADING_FORM
    ).asRootScreen()
  }

  @Composable
  private fun LoadingFormFailed(
    onBack: () -> Unit,
    onRetry: () -> Unit,
  ): ScreenModel {
    return ErrorFormBodyModel(
      title = "Couldn't load form",
      subline = "We were unable to load the feedback form. Please try again, or contact us on our website.",
      primaryButton =
        ButtonDataModel(
          text = "Retry",
          onClick = onRetry
        ),
      onBack = onBack,
      secondaryButton =
        ButtonDataModel(
          text = "Dismiss",
          onClick = onBack
        ),
      eventTrackerScreenId = FeedbackEventTrackerScreenId.FEEDBACK_LOAD_FAILED
    ).asModalScreen()
  }
}

private sealed interface FeedbackUiState {
  data object LoadingFormStructure : FeedbackUiState

  data object LoadingFormFailed : FeedbackUiState

  data class FillingForm(
    val initialData: SupportTicketData,
    val structure: SupportTicketForm,
  ) : FeedbackUiState
}
