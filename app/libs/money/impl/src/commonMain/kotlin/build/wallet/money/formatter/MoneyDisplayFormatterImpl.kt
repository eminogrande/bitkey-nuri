package build.wallet.money.formatter

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.money.BitcoinMoney
import build.wallet.money.FiatMoney
import build.wallet.money.Money
import build.wallet.money.display.BitcoinDisplayPreferenceRepository
import build.wallet.money.display.BitcoinDisplayUnit

@BitkeyInject(AppScope::class)
class MoneyDisplayFormatterImpl(
  private val bitcoinDisplayPreferenceRepository: BitcoinDisplayPreferenceRepository,
  private val moneyFormatterDefinitions: MoneyFormatterDefinitions,
) : MoneyDisplayFormatter {
  override fun format(amount: Money) =
    when (amount) {
      is FiatMoney -> format(amount)
      is BitcoinMoney -> format(amount)
    }

  override fun formatCompact(amount: FiatMoney) =
    moneyFormatterDefinitions.fiatCompact.stringValue(amount)

  private fun format(amount: FiatMoney) = moneyFormatterDefinitions.fiatStandard.stringValue(amount)

  private fun format(amount: BitcoinMoney) =
    when (bitcoinDisplayPreferenceRepository.bitcoinDisplayUnit.value) {
      BitcoinDisplayUnit.Satoshi -> moneyFormatterDefinitions.bitcoinFractionalNameOnly
      BitcoinDisplayUnit.Bitcoin -> moneyFormatterDefinitions.bitcoinReducedCode
    }.stringValue(amount)
}
