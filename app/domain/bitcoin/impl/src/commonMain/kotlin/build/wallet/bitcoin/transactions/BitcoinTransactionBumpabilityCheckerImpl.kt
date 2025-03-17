package build.wallet.bitcoin.transactions

import build.wallet.bdk.bindings.BdkUtxo
import build.wallet.bitcoin.transactions.BitcoinTransaction.ConfirmationStatus.Pending
import build.wallet.bitcoin.transactions.BitcoinTransaction.TransactionType.*
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import kotlinx.collections.immutable.ImmutableList

@BitkeyInject(AppScope::class)
class BitcoinTransactionBumpabilityCheckerImpl(
  private val sweepChecker: BitcoinTransactionSweepChecker,
  private val feeBumpAllowShrinkingChecker: FeeBumpAllowShrinkingChecker,
) : BitcoinTransactionBumpabilityChecker {
  override fun isBumpable(
    transaction: BitcoinTransaction,
    walletUnspentOutputs: ImmutableList<BdkUtxo>,
  ): Boolean {
    // A transaction must still be pending to be bumpable.
    if (transaction.confirmationStatus != Pending) {
      return false
    }

    // We currently do not support bumping on any incoming transaction. See W-8153. Explicitly checked
    // here as the sweep checker logic doesn't distinguish by transaction type.
    if (transaction.transactionType == Incoming) {
      return false
    }

    // A sweep is only bumpable if allow_shrinking is enabled, since there are no other inputs
    // we can pull in to pay the fees.
    if (sweepChecker.isSweep(transaction, walletUnspentOutputs)) {
      return feeBumpAllowShrinkingChecker.transactionSupportsAllowShrinking(
        transaction = transaction,
        walletUnspentOutputs = walletUnspentOutputs
      )
    }

    return when (transaction.transactionType) {
      Incoming -> false
      Outgoing -> true
      UtxoConsolidation -> {
        // UTXO Consolidations are very similar to sweeps and also require allow_shrinking in order
        // to pay for the fee bump if there are no other UTXOs available to pull in, unless we've
        // received more funds since the consolidation
        walletUnspentOutputs.size > 1 ||
          feeBumpAllowShrinkingChecker.transactionSupportsAllowShrinking(
            transaction = transaction,
            walletUnspentOutputs = walletUnspentOutputs
          )
      }
    }
  }
}
