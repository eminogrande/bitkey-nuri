package build.wallet.limit

import app.cash.turbine.test
import build.wallet.bitcoin.balance.BitcoinBalance
import build.wallet.bitcoin.transactions.BitcoinWalletServiceFake
import build.wallet.bitcoin.wallet.SpendingWalletMock
import build.wallet.bitkey.keybox.FullAccountMock
import build.wallet.coroutines.turbine.turbines
import build.wallet.f8e.mobilepay.MobilePayBalanceF8eClientMock
import build.wallet.f8e.mobilepay.MobilePayBalanceFailure
import build.wallet.ktor.result.HttpError
import build.wallet.ktor.test.HttpResponseMock
import build.wallet.limit.MobilePayStatus.MobilePayDisabled
import build.wallet.limit.MobilePayStatus.MobilePayEnabled
import build.wallet.money.BitcoinMoney
import build.wallet.money.FiatMoney
import build.wallet.platform.random.UuidGeneratorFake
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.ktor.http.*

class MobilePayStatusProviderImplTests : FunSpec({
  val spendingLimitDao = SpendingLimitDaoMock(turbines::create)
  val mobilePayBalanceF8eClient =
    MobilePayBalanceF8eClientMock(
      turbines::create,
      mobilePayBalance = MobilePayBalanceMock
    )
  val spendingWallet = SpendingWalletMock(turbines::create)
  val bitcoinWalletService = BitcoinWalletServiceFake()
  val statusProvider = MobilePayStatusRepositoryImpl(
    spendingLimitDao = spendingLimitDao,
    mobilePayBalanceF8eClient = mobilePayBalanceF8eClient,
    uuidGenerator = UuidGeneratorFake(),
    bitcoinWalletService = bitcoinWalletService
  )

  val limit1 = SpendingLimitMock(amount = FiatMoney.usd(100.0))

  beforeTest {
    mobilePayBalanceF8eClient.reset(MobilePayBalanceMock)
    spendingWallet.reset()
    bitcoinWalletService.reset()
    bitcoinWalletService.spendingWallet.value = spendingWallet
  }

  context("mobile pay was enabled locally") {
    beforeTest {
      spendingLimitDao.saveAndSetSpendingLimit(MobilePayBalanceMock.limit)
    }

    test("local and f8e are active") {
      statusProvider.status(FullAccountMock).test {
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        awaitItem().shouldBe(
          MobilePayEnabled(
            activeSpendingLimit = MobilePayBalanceMock.limit,
            balance = MobilePayBalanceMock
          )
        )
      }
    }

    test("use F8e as source of truth if F8e and App disagree on active state") {
      val disabledMobilePayBalance =
        MobilePayBalanceMock.copy(
          limit = MobilePayBalanceMock.limit.copy(active = false)
        )
      // Mock F8e returning inactive
      mobilePayBalanceF8eClient.mobilePayBalanceResult = Ok(disabledMobilePayBalance)

      statusProvider.status(FullAccountMock).test {
        // On the first network call, we realize that our spending limits don't match. We then
        // defer and persist the version from F8e instead, and check again.
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()

        awaitItem().shouldBe(
          MobilePayDisabled(mostRecentSpendingLimit = disabledMobilePayBalance.limit)
        )
      }
    }

    test("use F8e as source of truth if F8e and local DB values disagrees") {
      val f8eMobilePayBalance =
        MobilePayBalanceMock.copy(
          limit = limit1
        )
      mobilePayBalanceF8eClient.mobilePayBalanceResult = Ok(f8eMobilePayBalance)

      statusProvider.status(FullAccountMock).test {
        // On the first network call, we realize that our spending limits don't match. We then
        // defer and persist the version from F8e instead, and check again.
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()

        awaitItem().shouldBe(
          MobilePayEnabled(
            activeSpendingLimit = f8eMobilePayBalance.limit,
            balance = f8eMobilePayBalance
          )
        )
      }
    }

    test("show enabled with local information if network error is returned") {
      mobilePayBalanceF8eClient.mobilePayBalanceResult =
        Err(MobilePayBalanceFailure.F8eError(HttpError.NetworkError(Throwable())))

      statusProvider.status(FullAccountMock).test {
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()

        awaitItem().shouldBe(
          MobilePayEnabled(MobilePayBalanceMock.limit, null)
        )
      }
    }

    test("remove all limits if F8e never had any spending limit set") {
      mobilePayBalanceF8eClient.mobilePayBalanceResult =
        Err(
          MobilePayBalanceFailure.F8eError(
            HttpError.ServerError(
              response =
                HttpResponseMock(
                  HttpStatusCode.InternalServerError
                )
            )
          )
        )

      statusProvider.status(FullAccountMock).test {
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        spendingLimitDao.removeAllLimitsCalls.awaitItem()

        awaitItem().shouldBe(MobilePayDisabled(mostRecentSpendingLimit = null))
      }
    }

    test("disabling Mobile Pay should return previous limit") {
      mobilePayBalanceF8eClient.mobilePayBalanceResult = Ok(MobilePayBalanceMock)

      statusProvider.status(FullAccountMock).test {
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        awaitItem().shouldBe(
          MobilePayEnabled(
            activeSpendingLimit = MobilePayBalanceMock.limit,
            balance = MobilePayBalanceMock
          )
        )

        // Simulate disabling spending limit
        val disabledMobilePayBalance =
          MobilePayBalanceMock.copy(
            limit = MobilePayBalanceMock.limit.copy(active = false)
          )
        mobilePayBalanceF8eClient.mobilePayBalanceResult = Ok(disabledMobilePayBalance)
        spendingLimitDao.disableSpendingLimit()

        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        awaitItem().shouldBe(
          MobilePayDisabled(mostRecentSpendingLimit = disabledMobilePayBalance.limit)
        )
        spendingLimitDao.clearActiveLimitCalls.awaitItem()
      }
    }
  }

  context("mobile pay was disabled locally") {
    beforeTest {
      spendingLimitDao.reset()
    }

    test("mobile pay was never enabled on F8e") {
      mobilePayBalanceF8eClient.mobilePayBalanceResult =
        Err(
          MobilePayBalanceFailure.F8eError(
            HttpError.ServerError(
              response =
                HttpResponseMock(
                  HttpStatusCode.InternalServerError
                )
            )
          )
        )

      // We should show Mobile Pay as disabled.
      statusProvider.status(FullAccountMock).test {
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        awaitItem().shouldBe(MobilePayDisabled(mostRecentSpendingLimit = null))
      }
    }

    test("local and f8e are inactive") {
      val disabledLimit = MobilePayBalanceMock.limit.copy(active = false)
      mobilePayBalanceF8eClient.mobilePayBalanceResult =
        Ok(
          MobilePayBalanceMock.copy(
            limit = disabledLimit
          )
        )

      statusProvider.status(FullAccountMock).test {
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        awaitItem().shouldBe(MobilePayDisabled(mostRecentSpendingLimit = disabledLimit))

        // Update both F8e and local DB.
        mobilePayBalanceF8eClient.mobilePayBalanceResult = Ok(MobilePayBalanceMock)
        spendingLimitDao.saveAndSetSpendingLimit(limit = MobilePayBalanceMock.limit)

        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        awaitItem().shouldBe(
          MobilePayEnabled(
            activeSpendingLimit = MobilePayBalanceMock.limit,
            balance = MobilePayBalanceMock
          )
        )
      }
    }

    test("local is inactive, but f8e is active") {
      mobilePayBalanceF8eClient.mobilePayBalanceResult = Ok(MobilePayBalanceMock)

      statusProvider.status(FullAccountMock).test {
        // On the first network call, we realize that our spending limits don't match. We then
        // defer and persist the version from F8e instead, and check again.
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
        mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()

        awaitItem().shouldBe(
          MobilePayEnabled(
            activeSpendingLimit = MobilePayBalanceMock.limit,
            balance = MobilePayBalanceMock
          )
        )
      }
    }
  }

  test("transaction sync should trigger a re-fetch of MobilePayBalance") {
    val newSpent = MobilePayBalanceMock.copy(spent = BitcoinMoney.sats(1))
    mobilePayBalanceF8eClient.mobilePayBalanceResult = Ok(newSpent)

    statusProvider.status(FullAccountMock).test {
      mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
      awaitItem().shouldBe(
        MobilePayEnabled(
          activeSpendingLimit = MobilePayBalanceMock.limit,
          balance = newSpent
        )
      )

      spendingWallet.balanceFlow.value = BitcoinBalance.ZeroBalance

      mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
      awaitItem().shouldBe(
        MobilePayEnabled(
          activeSpendingLimit = MobilePayBalanceMock.limit,
          balance = newSpent
        )
      )
    }
  }

  test("on demand refresh should refetch MobilePayBalance") {
    statusProvider.status(FullAccountMock).test {
      mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
      awaitItem().shouldBe(
        MobilePayEnabled(
          activeSpendingLimit = MobilePayBalanceMock.limit,
          balance = MobilePayBalanceMock
        )
      )

      statusProvider.refreshStatus()
      mobilePayBalanceF8eClient.mobilePayBalanceCalls.awaitItem()
      awaitItem().shouldBe(
        MobilePayEnabled(
          activeSpendingLimit = MobilePayBalanceMock.limit,
          balance = MobilePayBalanceMock
        )
      )
    }
  }
})
