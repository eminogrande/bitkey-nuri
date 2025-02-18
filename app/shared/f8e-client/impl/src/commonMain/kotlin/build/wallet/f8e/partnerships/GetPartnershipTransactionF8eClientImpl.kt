package build.wallet.f8e.partnerships

import build.wallet.bitkey.f8e.AccountId
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.f8e.F8eEnvironment
import build.wallet.f8e.client.F8eHttpClient
import build.wallet.f8e.client.plugins.withAccountId
import build.wallet.f8e.client.plugins.withEnvironment
import build.wallet.f8e.logging.withDescription
import build.wallet.ktor.result.NetworkingError
import build.wallet.ktor.result.RedactedResponseBody
import build.wallet.ktor.result.bodyResult
import build.wallet.partnerships.PartnerId
import build.wallet.partnerships.PartnershipTransactionId
import build.wallet.partnerships.PartnershipTransactionType
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.map
import io.ktor.client.request.get
import io.ktor.client.request.parameter
import kotlinx.serialization.Serializable

@BitkeyInject(AppScope::class)
class GetPartnershipTransactionF8eClientImpl(
  private val client: F8eHttpClient,
) : GetPartnershipTransactionF8eClient {
  override suspend fun getPartnershipTransaction(
    accountId: AccountId,
    f8eEnvironment: F8eEnvironment,
    partner: PartnerId,
    partnershipTransactionId: PartnershipTransactionId,
    transactionType: PartnershipTransactionType,
  ): Result<F8ePartnershipTransaction, NetworkingError> {
    return client
      .authenticated()
      .bodyResult<PartnershipTransactionResponse> {
        get("/api/partnerships/partners/${partner.value}/transactions/${partnershipTransactionId.value}") {
          parameter("type", transactionType.name)
          withDescription("Get partnership transaction")
          withEnvironment(f8eEnvironment)
          withAccountId(accountId)
        }
      }
      .map {
        it.transaction
      }
  }

  @Serializable
  internal data class PartnershipTransactionResponse(
    val transaction: F8ePartnershipTransaction,
  ) : RedactedResponseBody
}
