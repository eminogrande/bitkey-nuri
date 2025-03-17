package build.wallet.home

import app.cash.turbine.Turbine
import build.wallet.home.GettingStartedTask.TaskId
import build.wallet.home.GettingStartedTask.TaskState
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow

class GettingStartedTaskDaoMock(
  turbine: (name: String) -> Turbine<Unit>,
  initialTasks: List<GettingStartedTask> = emptyList(),
) : GettingStartedTaskDao {
  val clearTasksCalls = turbine("clear task calls")
  val gettingStartedTasks = MutableStateFlow(initialTasks)

  override suspend fun getTasks() = gettingStartedTasks.value

  override fun tasks(): Flow<List<GettingStartedTask>> = gettingStartedTasks

  var addTasksResult: Result<Unit, Error> = Ok(Unit)

  override suspend fun addTasks(tasks: List<GettingStartedTask>): Result<Unit, Error> {
    gettingStartedTasks.emit(tasks)
    return addTasksResult
  }

  var updateTaskResult: Result<Unit, Error> = Ok(Unit)

  override suspend fun updateTask(
    id: TaskId,
    state: TaskState,
  ): Result<Unit, Error> {
    val tasks = gettingStartedTasks.value.toMutableList()
    val index = tasks.indexOfFirst { it.id == id }
    tasks[index] = tasks[index].copy(state = state)
    gettingStartedTasks.emit(tasks)
    return updateTaskResult
  }

  var clearTasksResult: Result<Unit, Error> = Ok(Unit)

  override suspend fun clearTasks(): Result<Unit, Error> {
    clearTasksCalls.add(Unit)
    reset()
    return clearTasksResult
  }

  fun reset() {
    gettingStartedTasks.value = emptyList()
  }
}
