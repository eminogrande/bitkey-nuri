package build.wallet.partnerships

import build.wallet.database.sqldelight.PartnershipTransactionEntity
import build.wallet.money.currency.code.IsoCurrencyTextCode
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.doubles.plusOrMinus
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Instant
import kotlin.time.Duration.Companion.minutes

class PartnershipTransactionEntityTest : FunSpec({
  val instantIso8601 = "2024-11-15T18:57:59.718602Z"
  val instant = Instant.parse(instantIso8601)
  test("Model Conversion") {
    val entity = PartnershipTransactionEntity(
      transactionId = PartnershipTransactionId("test-id"),
      partnerId = PartnerId("test-partner"),
      partnerName = "test-partner-name",
      partnerLogoUrl = "test-partner-logo-url",
      context = "test-context",
      type = PartnershipTransactionType.PURCHASE,
      status = PartnershipTransactionStatus.PENDING,
      cryptoAmount = 1.23,
      txid = "test-transaction-hash",
      fiatAmount = 3.21,
      fiatCurrency = IsoCurrencyTextCode("USD"),
      paymentMethod = "test-payment-method",
      created = instant,
      updated = instant + 1.minutes,
      sellWalletAddress = "test-sell-wallet-address",
      partnerTransactionUrl = "https://fake-partner.com/transaction/test-id",
      partnerLogoBadgedUrl = "test-partner-logo-badged-url"
    )

    val model = entity.toModel()

    model.id.value.shouldBe("test-id")
    model.partnerInfo.partnerId.value.shouldBe("test-partner")
    model.partnerInfo.name.shouldBe("test-partner-name")
    model.partnerInfo.logoUrl.shouldBe("test-partner-logo-url")
    model.context.shouldBe("test-context")
    model.type.shouldBe(PartnershipTransactionType.PURCHASE)
    model.status.shouldBe(PartnershipTransactionStatus.PENDING)
    model.cryptoAmount.shouldBe(1.23.plusOrMinus(1e-16))
    model.txid.shouldBe("test-transaction-hash")
    model.fiatAmount.shouldBe(3.21.plusOrMinus(1e-16))
    model.fiatCurrency?.code.shouldBe("USD")
    model.paymentMethod.shouldBe("test-payment-method")
    model.created.shouldBe(instant)
    model.updated.shouldBe(instant + 1.minutes)
    model.sellWalletAddress.shouldBe("test-sell-wallet-address")
    model.partnerTransactionUrl.shouldBe("https://fake-partner.com/transaction/test-id")
    model.partnerInfo.logoBadgedUrl.shouldBe("test-partner-logo-badged-url")
  }

  test("Entity Conversion") {
    val model = PartnershipTransaction(
      id = PartnershipTransactionId("test-id"),
      partnerInfo = PartnerInfo(
        partnerId = PartnerId("test-partner"),
        name = "test-partner-name",
        logoUrl = "test-partner-logo-url",
        logoBadgedUrl = "test-partner-logo-badged-url"
      ),
      context = "test-context",
      type = PartnershipTransactionType.PURCHASE,
      status = PartnershipTransactionStatus.PENDING,
      cryptoAmount = 1.23,
      txid = "test-transaction-hash",
      fiatAmount = 3.21,
      fiatCurrency = IsoCurrencyTextCode("USD"),
      paymentMethod = "test-payment-method",
      created = instant,
      updated = instant + 1.minutes,
      sellWalletAddress = "test-sell-wallet-address",
      partnerTransactionUrl = "https://fake-partner.com/transaction/test-id"
    )

    val entity = model.toEntity()

    entity.transactionId.value.shouldBe("test-id")
    entity.partnerId.value.shouldBe("test-partner")
    entity.partnerName.shouldBe("test-partner-name")
    entity.partnerLogoUrl.shouldBe("test-partner-logo-url")
    entity.context.shouldBe("test-context")
    entity.type.shouldBe(PartnershipTransactionType.PURCHASE)
    entity.status.shouldBe(PartnershipTransactionStatus.PENDING)
    entity.cryptoAmount.shouldBe(1.23.plusOrMinus(1e-16))
    entity.txid.shouldBe("test-transaction-hash")
    entity.fiatAmount.shouldBe(3.21.plusOrMinus(1e-16))
    entity.fiatCurrency?.code.shouldBe("USD")
    entity.paymentMethod.shouldBe("test-payment-method")
    entity.created.shouldBe(instant)
    entity.updated.shouldBe(instant + 1.minutes)
    entity.sellWalletAddress.shouldBe("test-sell-wallet-address")
    entity.partnerTransactionUrl.shouldBe("https://fake-partner.com/transaction/test-id")
  }
})
