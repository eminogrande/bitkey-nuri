package build.wallet.bitcoin.address

import build.wallet.worker.AppWorker

/**
 * Registers [bitcoin addresses][BitcoinAddress] generated by [BitcoinAddressService] with f8e for notifications.
 */
interface BitcoinRegisterWatchAddressWorker : AppWorker
