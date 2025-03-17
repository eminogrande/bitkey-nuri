package build.wallet.support

import build.wallet.bitkey.f8e.AccountId
import com.github.michaelbull.result.Result

/**
 * Repository taking care of loading support ticket form structure,
 * creating a new ticket, and provide initial values for form fields.
 */
interface SupportTicketRepository {
  /**
   * Creates a new support ticket from the provided [data].
   */
  suspend fun createTicket(
    accountId: AccountId,
    form: SupportTicketForm,
    data: SupportTicketData,
  ): Result<Unit, Error>

  /**
   * Fetches the structure of the ticket form from backend.
   */
  suspend fun loadFormStructure(accountId: AccountId): Result<SupportTicketForm, Error>

  /**
   * Returns an instance of [SupportTicketData] populated with available values
   * for [SupportTicketField.KnownFieldType] fields.
   */
  suspend fun prefillKnownFields(form: SupportTicketForm): SupportTicketData
}
