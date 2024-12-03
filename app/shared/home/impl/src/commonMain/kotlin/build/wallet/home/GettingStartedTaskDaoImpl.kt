package build.wallet.home

import build.wallet.database.BitkeyDatabaseProvider
import build.wallet.home.GettingStartedTask.TaskId
import build.wallet.home.GettingStartedTask.TaskState
import build.wallet.logging.logFailure
import build.wallet.sqldelight.asFlowOfList
import build.wallet.sqldelight.awaitAsListResult
import build.wallet.sqldelight.awaitTransaction
import com.github.michaelbull.result.mapOr
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import kotlinx.coroutines.flow.*

class GettingStartedTaskDaoImpl(
  private val databaseProvider: BitkeyDatabaseProvider,
) : GettingStartedTaskDao {
  override fun tasks() =
    flow { emit(databaseProvider.database()) }
      .flatMapLatest { database ->
        database.gettingStartedTaskQueries
          .allGettingStartedTasks()
          .asFlowOfList()
      }
      .transformLatest { queryResult ->
        queryResult
          .logFailure { "Failed to read onboarding task from database" }
          .onSuccess { entities ->
            emit(entities.map { GettingStartedTask(id = it.taskId, state = it.taskState) })
          }
          .onFailure {
            emit(emptyList<GettingStartedTask>())
          }
      }
      .distinctUntilChanged()

  override suspend fun getTasks(): List<GettingStartedTask> =
    databaseProvider.database().gettingStartedTaskQueries
      .allGettingStartedTasks()
      .awaitAsListResult()
      .logFailure { "Failed to read onboarding task from database" }
      .mapOr(emptyList()) { entities ->
        entities.map { GettingStartedTask(id = it.taskId, state = it.taskState) }
      }

  override suspend fun addTasks(tasks: List<GettingStartedTask>) =
    databaseProvider.database().gettingStartedTaskQueries
      .awaitTransaction {
        tasks.forEach { insertGettingStartedTask(taskId = it.id, taskState = it.state) }
      }

  override suspend fun updateTask(
    id: TaskId,
    state: TaskState,
  ) = databaseProvider.database().gettingStartedTaskQueries
    .awaitTransaction { updateGettingStartedTask(taskId = id, taskState = state) }
    .logFailure { "Error updating Getting Started task $id with state $state" }

  override suspend fun clearTasks() =
    databaseProvider.database().gettingStartedTaskQueries
      .awaitTransaction { clearGettingStartedTasks() }
}
