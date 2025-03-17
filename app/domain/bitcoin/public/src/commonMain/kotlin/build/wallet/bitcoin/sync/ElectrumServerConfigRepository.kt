package build.wallet.bitcoin.sync

import com.github.michaelbull.result.Result
import kotlinx.coroutines.flow.Flow

interface ElectrumServerConfigRepository {
  /**
   * Update locally-persisted Electrum configuration provided by F8e
   */
  suspend fun storeF8eDefinedElectrumConfig(
    electrumServerDetails: ElectrumServerDetails,
  ): Result<Unit, Error>

  /**
   * Update locally-persisted Electrum preference provided by the user
   */
  suspend fun storeUserPreference(preference: ElectrumServerPreferenceValue): Result<Unit, Error>

  /**
   * Get current locally-persisted Electrum server state information.
   */
  fun getUserElectrumServerPreference(): Flow<ElectrumServerPreferenceValue?>

  /**
   * Get current locally-persisted F8e server information.
   */
  fun getF8eDefinedElectrumServer(): Flow<ElectrumServer?>
}
