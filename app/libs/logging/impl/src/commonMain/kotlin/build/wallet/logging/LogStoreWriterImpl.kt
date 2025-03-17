package build.wallet.logging

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.logging.dev.LogStore
import build.wallet.logging.dev.LogStore.Entity
import build.wallet.logging.dev.LogStoreWriter
import co.touchlab.kermit.Severity
import co.touchlab.kermit.Severity.Assert
import co.touchlab.kermit.Severity.Debug
import co.touchlab.kermit.Severity.Error
import co.touchlab.kermit.Severity.Info
import co.touchlab.kermit.Severity.Verbose
import co.touchlab.kermit.Severity.Warn
import kotlinx.datetime.Clock

@BitkeyInject(AppScope::class)
class LogStoreWriterImpl(
  private val logStore: LogStore,
  private val clock: Clock,
) : LogStoreWriter() {
  override fun log(
    severity: Severity,
    message: String,
    tag: String,
    throwable: Throwable?,
  ) {
    logStore.record(
      Entity(
        time = clock.now(),
        level = severity.toLogLevel(),
        tag = tag,
        throwable = throwable,
        message = message
      )
    )
  }
}

internal fun Severity.toLogLevel(): LogLevel {
  return when (this) {
    Verbose -> LogLevel.Verbose
    Debug -> LogLevel.Debug
    Info -> LogLevel.Info
    Warn -> LogLevel.Warn
    Error -> LogLevel.Error
    Assert -> LogLevel.Assert
  }
}
