package bitkey.account

import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.f8e.F8eEnvironment

/**
 * Defines environment configuration for [build.wallet.bitkey.account.LiteAccount]s.
 */
data class LiteAccountConfig(
  override val bitcoinNetworkType: BitcoinNetworkType,
  override val f8eEnvironment: F8eEnvironment,
  override val isTestAccount: Boolean,
  override val isUsingSocRecFakes: Boolean,
) : AccountConfig
