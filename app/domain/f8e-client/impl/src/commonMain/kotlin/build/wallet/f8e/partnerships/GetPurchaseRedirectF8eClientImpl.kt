package build.wallet.f8e.partnerships

import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.bitkey.f8e.FullAccountId
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.f8e.F8eEnvironment
import build.wallet.f8e.client.F8eHttpClient
import build.wallet.f8e.client.plugins.withAccountId
import build.wallet.f8e.client.plugins.withEnvironment
import build.wallet.f8e.partnerships.GetPurchaseRedirectF8eClient.Success
import build.wallet.ktor.result.NetworkingError
import build.wallet.ktor.result.RedactedRequestBody
import build.wallet.ktor.result.RedactedResponseBody
import build.wallet.ktor.result.bodyResult
import build.wallet.ktor.result.setRedactedBody
import build.wallet.money.FiatMoney
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.map
import io.ktor.client.request.post
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@BitkeyInject(AppScope::class)
class GetPurchaseRedirectF8eClientImpl(
  private val f8eHttpClient: F8eHttpClient,
) : GetPurchaseRedirectF8eClient {
  override suspend fun purchaseRedirect(
    fullAccountId: FullAccountId,
    address: BitcoinAddress,
    f8eEnvironment: F8eEnvironment,
    fiatAmount: FiatMoney,
    partner: String,
    paymentMethod: String,
    quoteId: String?,
  ): Result<Success, NetworkingError> {
    return f8eHttpClient
      .authenticated()
      .bodyResult<ResponseBody> {
        post("/api/partnerships/purchases/redirects") {
          withEnvironment(f8eEnvironment)
          withAccountId(fullAccountId)
          setRedactedBody(
            RequestBody(
              address = address.address,
              fiatAmount = fiatAmount.value.doubleValue(exactRequired = false),
              fiatCurrency = fiatAmount.currency.textCode.code.uppercase(),
              partner = partner,
              paymentMethod = paymentMethod,
              quoteId = quoteId
            )
          )
        }
      }
      .map { body ->
        Success(
          body.redirectInfo
        )
      }
  }

  @Serializable
  private data class RequestBody(
    val address: String,
    @SerialName("fiat_amount")
    val fiatAmount: Double,
    @SerialName("fiat_currency")
    val fiatCurrency: String,
    val partner: String,
    @SerialName("payment_method")
    val paymentMethod: String,
    @SerialName("quote_id")
    val quoteId: String?,
  ) : RedactedRequestBody

  @Serializable
  private data class ResponseBody(
    @SerialName("redirect_info")
    val redirectInfo: RedirectInfo,
  ) : RedactedResponseBody
}
