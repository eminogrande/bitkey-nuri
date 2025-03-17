package build.wallet.fwup

import app.cash.turbine.Turbine
import app.cash.turbine.plusAssign
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import kotlinx.coroutines.flow.MutableStateFlow

class FwupDataDaoMock(
  private val turbine: (name: String) -> Turbine<Any>,
) : FwupDataDao {
  var clearCalls = turbine("clear fwup data dao calls")
  var setFwupDataCalls = turbine("set fwup data dao calls")

  val fwupDataFlow = MutableStateFlow<Result<FwupData?, Error>>(Ok(null))

  override fun fwupData() = fwupDataFlow

  override suspend fun setFwupData(fwupData: FwupData): Result<Unit, Error> {
    setFwupDataCalls += fwupData
    return Ok(Unit)
  }

  override suspend fun clear(): Result<Unit, Error> {
    clearCalls += Unit
    return Ok(Unit)
  }

  override suspend fun setSequenceId(sequenceId: UInt): Result<Unit, Error> {
    return Ok(Unit)
  }

  override suspend fun getSequenceId(): Result<UInt, Error> {
    return Ok(0u)
  }

  fun reset(testName: String) {
    fwupDataFlow.value = Ok(null)
    clearCalls = turbine("clear fwup data dao calls for $testName")
    setFwupDataCalls = turbine("set fwup data dao calls for $testName")
  }
}
