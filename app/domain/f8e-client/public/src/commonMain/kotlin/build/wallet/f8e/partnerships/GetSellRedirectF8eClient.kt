package build.wallet.f8e.partnerships

import build.wallet.bitkey.f8e.FullAccountId
import build.wallet.f8e.F8eEnvironment
import build.wallet.money.BitcoinMoney
import build.wallet.money.FiatMoney
import com.github.michaelbull.result.Result

interface GetSellRedirectF8eClient {
  suspend fun sellRedirect(
    fullAccountId: FullAccountId,
    f8eEnvironment: F8eEnvironment,
    fiatAmount: FiatMoney,
    bitcoinAmount: BitcoinMoney,
    partner: String,
  ): Result<Success, Error>

  /**
   * A struct representing the redirect information needed to present the partner experience
   *
   * @property redirectInfo struct including the URL and its type
   */
  data class Success(val redirectInfo: RedirectInfo)
}
