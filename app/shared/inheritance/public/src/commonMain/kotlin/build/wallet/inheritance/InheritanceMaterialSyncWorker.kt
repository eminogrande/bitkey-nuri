package build.wallet.inheritance

import build.wallet.bitkey.keybox.Keybox
import build.wallet.feature.FeatureFlagValue
import build.wallet.feature.flags.InheritanceFeatureFlag
import build.wallet.feature.isEnabled
import build.wallet.keybox.KeyboxDao
import build.wallet.logging.logError
import build.wallet.logging.logVerbose
import build.wallet.logging.logWarn
import build.wallet.worker.AppWorker
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.isActive
import kotlin.time.Duration.Companion.minutes

/**
 * Triggers an inheritance material sync whenever keys or contacts change.
 */
class InheritanceMaterialSyncWorker(
  private val inheritanceService: InheritanceService,
  private val inheritanceRelationshipsProvider: InheritanceRelationshipsProvider,
  private val keyboxDao: KeyboxDao,
  private val featureFlag: InheritanceFeatureFlag,
) : AppWorker {
  override suspend fun executeWork() {
    combine(
      inheritanceRelationshipsProvider.endorsedInheritanceContacts,
      keyboxDao.activeKeybox(),
      featureFlag.flagValue()
    ) { _, keybox, flag ->
      flag to keybox
    }.collectLatest { (flag, keyboxResult) ->
      syncInheritanceMaterial(flag, keyboxResult)
    }
  }

  private suspend fun syncInheritanceMaterial(
    flagState: FeatureFlagValue.BooleanFlag,
    keyboxResult: Result<Keybox?, Error>,
  ) {
    if (!flagState.isEnabled()) {
      logVerbose { "Skipping Inheritance Material Sync: Feature Disabled" }
      return
    }
    if (keyboxResult.isErr) {
      logWarn(throwable = keyboxResult.error) {
        "Skipping Inheritance Material Sync: Keybox Error"
      }
      return
    }
    val keybox = keyboxResult.get() ?: run {
      logVerbose { "Skipping Inheritance Material Sync: No Keybox" }
      return
    }

    while (currentCoroutineContext().isActive) {
      inheritanceService.syncInheritanceMaterial(keybox)
        .onFailure {
          logError(throwable = it) { "Failed to sync inheritance material" }
        }
        .onSuccess {
          logVerbose { "Inheritance Material Synced" }
          return
        }
      delay(1.minutes)
    }
  }
}
