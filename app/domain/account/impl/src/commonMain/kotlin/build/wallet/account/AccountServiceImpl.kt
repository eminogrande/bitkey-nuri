package build.wallet.account

import build.wallet.account.AccountStatus.*
import build.wallet.bitkey.account.Account
import build.wallet.bitkey.account.FullAccount
import build.wallet.bitkey.account.LiteAccount
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.fold
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.mapLatest

@BitkeyInject(AppScope::class)
class AccountServiceImpl(
  private val accountDao: AccountDao,
) : AccountService {
  override fun accountStatus(): Flow<Result<AccountStatus, Error>> {
    return combine(
      accountDao.activeAccount(),
      accountDao.onboardingAccount()
    ) { activeAccountResult, onboardingAccountResult ->
      coroutineBinding {
        val activeAccount = activeAccountResult.bind()
        val onboardingAccount = onboardingAccountResult.bind()

        if (activeAccount != null) {
          // We have active account, check if we also have an onboarding full account
          // (i.e. Lite Account is upgrading).
          if (activeAccount is LiteAccount && onboardingAccount is FullAccount) {
            LiteAccountUpgradingToFullAccount(
              liteAccount = activeAccount,
              onboardingAccount = onboardingAccount
            )
          } else {
            ActiveAccount(activeAccount)
          }
        } else {
          // No active account, checking onboarding account
          if (onboardingAccount != null) {
            // We have onboarding account
            OnboardingAccount(onboardingAccount)
          } else {
            // We have no account data
            NoAccount
          }
        }
      }
    }
      .distinctUntilChanged()
  }

  override fun activeAccount(): Flow<Account?> {
    return accountStatus()
      .mapLatest { result ->
        result.fold(
          success = { status -> (status as? ActiveAccount)?.account },
          failure = { null }
        )
      }
      .distinctUntilChanged()
  }

  override suspend fun clear(): Result<Unit, Error> {
    return accountDao.clear()
  }

  override suspend fun setActiveAccount(account: Account): Result<Unit, Error> {
    return accountDao.setActiveAccount(account)
  }

  override suspend fun saveAccountAndBeginOnboarding(account: Account): Result<Unit, Error> {
    return accountDao.saveAccountAndBeginOnboarding(account)
  }
}
