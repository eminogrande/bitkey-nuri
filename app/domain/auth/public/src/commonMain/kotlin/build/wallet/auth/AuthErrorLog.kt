package build.wallet.auth

import build.wallet.logging.LogLevel.Error
import build.wallet.logging.LogLevel.Warn
import build.wallet.logging.logInternal
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.onFailure

/**
 * Convenience to log auth errors, separating the severity
 * for expected f8e auth errors, [AuthProtocolError],
 * from other unexpected errors.
 */
inline fun <V, E : AuthError> Result<V, E>.logAuthFailure(message: () -> String): Result<V, E> =
  onFailure { error ->
    logInternal(
      level = when (error) {
        is AuthProtocolError -> Warn
        else -> Error
      },
      throwable = error
    ) { "${message()}. $error" }
  }
