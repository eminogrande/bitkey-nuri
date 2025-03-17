package build.wallet.bitkey.recovery

import build.wallet.bitkey.hardware.HwKeyBundle

data class HardwareKeysForRecovery(
  /**
   * The new key bundle that the HW will use once recovery is complete.
   * Will be the HW portion of the App and Server SpendingKeyset we are sweeping to.
   */
  val newKeyBundle: HwKeyBundle,
)
