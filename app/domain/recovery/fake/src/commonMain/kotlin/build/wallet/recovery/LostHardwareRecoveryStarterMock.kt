package build.wallet.bitcoin.recovery

import app.cash.turbine.Turbine
import app.cash.turbine.plusAssign
import build.wallet.bitkey.app.AppKeyBundle
import build.wallet.bitkey.hardware.AppGlobalAuthKeyHwSignature
import build.wallet.bitkey.hardware.HwKeyBundle
import build.wallet.recovery.LostHardwareRecoveryStarter
import build.wallet.recovery.LostHardwareRecoveryStarter.InitiateDelayNotifyHardwareRecoveryError
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result

class LostHardwareRecoveryStarterMock(
  turbine: (String) -> Turbine<Any>,
) : LostHardwareRecoveryStarter {
  val initiateCalls = turbine("initiate calls")
  var initiateResult: Result<Unit, InitiateDelayNotifyHardwareRecoveryError> = Ok(Unit)

  override suspend fun initiate(
    destinationAppKeyBundle: AppKeyBundle,
    destinationHardwareKeyBundle: HwKeyBundle,
    appGlobalAuthKeyHwSignature: AppGlobalAuthKeyHwSignature,
  ): Result<Unit, InitiateDelayNotifyHardwareRecoveryError> {
    initiateCalls += Unit
    return initiateResult
  }

  fun reset() {
    initiateResult = Ok(Unit)
  }
}
