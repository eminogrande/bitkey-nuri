package build.wallet.f8e.auth

import bitkey.auth.AccountAuthTokens
import bitkey.auth.AuthTokenScope
import bitkey.auth.RefreshToken
import build.wallet.bitkey.app.AppAuthKey
import build.wallet.bitkey.hardware.HwAuthPublicKey
import build.wallet.crypto.PublicKey
import build.wallet.f8e.F8eEnvironment
import build.wallet.ktor.result.NetworkingError
import build.wallet.ktor.result.RedactedResponseBody
import com.github.michaelbull.result.Result
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

interface AuthF8eClient {
  suspend fun initiateAuthentication(
    f8eEnvironment: F8eEnvironment,
    authPublicKey: HwAuthPublicKey,
  ): Result<InitiateAuthenticationSuccess, NetworkingError>

  suspend fun initiateAuthentication(
    f8eEnvironment: F8eEnvironment,
    authPublicKey: PublicKey<out AppAuthKey>,
    tokenScope: AuthTokenScope,
  ): Result<InitiateAuthenticationSuccess, NetworkingError>

  suspend fun initiateHardwareAuthentication(
    f8eEnvironment: F8eEnvironment,
    authPublicKey: HwAuthPublicKey,
  ): Result<InitiateHardwareAuthenticationSuccess, NetworkingError>

  @Serializable
  data class InitiateAuthenticationSuccess(
    val username: String,
    @SerialName("account_id")
    val accountId: String,
    val challenge: String,
    val session: String,
  ) : RedactedResponseBody

  @Serializable
  data class InitiateHardwareAuthenticationSuccess(
    @SerialName("account_id")
    val accountId: String,
    val challenge: String,
    val session: String,
  ) : RedactedResponseBody

  suspend fun completeAuthentication(
    f8eEnvironment: F8eEnvironment,
    username: String,
    challengeResponse: String,
    session: String,
  ): Result<AccountAuthTokens, NetworkingError>

  suspend fun refreshToken(
    f8eEnvironment: F8eEnvironment,
    refreshToken: RefreshToken,
  ): Result<AccountAuthTokens, NetworkingError>
}
