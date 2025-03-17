package build.wallet.onboarding

import build.wallet.cloud.backup.csek.SealedCsek

/**
 * Represents a single step in the account onboarding process.
 */
sealed interface OnboardAccountStep {
  /**
   * Represents the step where the customer needs to complete the cloud backup setup.
   *
   * @param sealedCsek in case of full account, sealed CSEK to be used for creating full account
   * cloud backup.
   */
  data class CloudBackup(
    val sealedCsek: SealedCsek?,
  ) : OnboardAccountStep

  /**
   * Represents the step where the customer needs to complete the notification preferences setup.
   */
  data object NotificationPreferences : OnboardAccountStep
}
