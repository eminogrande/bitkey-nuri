package build.wallet.statemachine.moneyhome.card.bitcoinprice

import androidx.compose.runtime.*
import build.wallet.compose.collections.emptyImmutableList
import build.wallet.di.ActivityScope
import build.wallet.di.BitkeyInject
import build.wallet.money.BitcoinMoney
import build.wallet.money.currency.BTC
import build.wallet.money.display.FiatCurrencyPreferenceRepository
import build.wallet.money.exchange.CurrencyConverter
import build.wallet.money.formatter.MoneyDisplayFormatter
import build.wallet.pricechart.*
import build.wallet.statemachine.moneyhome.card.CardModel
import build.wallet.time.DateTimeFormatter
import build.wallet.time.TimeZoneProvider
import com.github.michaelbull.result.onSuccess
import com.ionspin.kotlin.bignum.decimal.BigDecimal
import com.ionspin.kotlin.bignum.decimal.DecimalMode
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.*
import kotlinx.datetime.toLocalDateTime
import org.jetbrains.compose.resources.getString

private const val SPARKLINE_MAX_POINTS = 50

@BitkeyInject(ActivityScope::class)
class BitcoinPriceCardUiStateMachineImpl(
  private val appScope: CoroutineScope,
  private val timeZoneProvider: TimeZoneProvider,
  private val bitcoinPriceCardPreference: BitcoinPriceCardPreference,
  private val dateTimeFormatter: DateTimeFormatter,
  private val moneyDisplayFormatter: MoneyDisplayFormatter,
  private val chartDataFetcherService: ChartDataFetcherService,
  private val fiatCurrencyPreferenceRepository: FiatCurrencyPreferenceRepository,
  private val currencyConverter: CurrencyConverter,
  private val chartRangePreference: ChartRangePreference,
) : BitcoinPriceCardUiStateMachine {
  private val isLoadingFlow = MutableStateFlow(true)
  private val dataFlow = MutableStateFlow<ImmutableList<DataPoint>>(emptyImmutableList())
  private val priceDirection = mutableStateOf(PriceDirection.STABLE)
  private val fiatCurrencyFlow = fiatCurrencyPreferenceRepository.fiatCurrencyPreference
  private val lastUpdatedFlow =
    fiatCurrencyFlow
      .flatMapLatest { fiatCurrency ->
        currencyConverter.latestRateTimestamp(BTC, fiatCurrency)
      }
      .filterNotNull()
      .map { updateTime ->
        val localTime = updateTime.toLocalDateTime(timeZoneProvider.current())
        "Updated ${dateTimeFormatter.localTime(localTime)}"
      }
      .stateIn(appScope, SharingStarted.WhileSubscribed(), "")
  private val priceMoneyFlow =
    fiatCurrencyFlow
      .flatMapLatest { fiatCurrency ->
        val btc = BitcoinMoney.btc(1.0)
        currencyConverter.convert(btc, fiatCurrency, null)
      }
      .stateIn(appScope, SharingStarted.WhileSubscribed(), null)
  private val priceChangeFlow =
    combine(priceMoneyFlow, dataFlow, chartRangePreference.selectedRange) { priceMoney, data, timeScale ->
      val end = priceMoney?.value?.doubleValue(exactRequired = false) ?: return@combine null
      val start = data.firstOrNull()?.y ?: return@combine null
      val diffPercent = (end - start) / start * 100
      val diffDecimal = BigDecimal.fromDouble(diffPercent, DecimalMode.US_CURRENCY)
      priceDirection.value = PriceDirection.from(diffDecimal)
      isLoadingFlow.update { false }
      "${diffDecimal.abs().toPlainString()}% ${timeScale.getPriceChangeLabel().lowercase()}"
    }
      .filterNotNull()
      .stateIn(appScope, SharingStarted.WhileSubscribed(), "0% today")

  @Composable
  override fun model(props: BitcoinPriceCardUiProps): CardModel? {
    val enabled by remember { bitcoinPriceCardPreference.isEnabled }.collectAsState()
    if (!enabled) {
      return null
    }
    val data by dataFlow.collectAsState()
    val isLoading by isLoadingFlow.collectAsState()
    val fiatCurrency by fiatCurrencyFlow.collectAsState()
    val lastUpdated by lastUpdatedFlow.collectAsState()
    val priceMoney by priceMoneyFlow.collectAsState()
    val price by remember {
      derivedStateOf {
        priceMoney?.let(moneyDisplayFormatter::format).orEmpty()
      }
    }
    val chartHistory by chartRangePreference.selectedRange.collectAsState()
    val priceChange by priceChangeFlow.collectAsState()
    LaunchedEffect(priceMoney, fiatCurrency, chartHistory, chartRangePreference.selectedRange.value) {
      if (priceMoney != null) {
        chartDataFetcherService.getChartData(
          range = chartRangePreference.selectedRange.value,
          maxPricePoints = SPARKLINE_MAX_POINTS
        ).onSuccess { chartData ->
          val list = chartData.toImmutableList()
          dataFlow.update { list }
        }
      }
    }

    return CardModel(
      title = null,
      content = CardModel.CardContent.BitcoinPrice(
        data = data,
        price = price,
        priceChange = priceChange,
        priceDirection = priceDirection.value,
        lastUpdated = lastUpdated,
        isLoading = isLoading
      ),
      onClick = props.onOpenPriceChart,
      style = CardModel.CardStyle.Outline
    )
  }

  private suspend fun ChartRange.getPriceChangeLabel(): String {
    return when (this) {
      ChartRange.DAY -> "today"
      ChartRange.WEEK, ChartRange.MONTH, ChartRange.YEAR, ChartRange.ALL -> getString(this.diffLabel)
    }
  }
}
