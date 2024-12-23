package build.wallet.f8e.demo

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.f8e.F8eEnvironment
import build.wallet.f8e.client.UnauthenticatedF8eHttpClient
import build.wallet.f8e.client.plugins.withEnvironment
import build.wallet.ktor.result.EmptyResponseBody
import build.wallet.ktor.result.RedactedRequestBody
import build.wallet.ktor.result.bodyResult
import build.wallet.ktor.result.setRedactedBody
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.mapError
import dev.zacsweers.redacted.annotations.Unredacted
import io.ktor.client.request.post
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@BitkeyInject(AppScope::class)
class DemoModeF8eClientImpl(
  private val f8eHttpClient: UnauthenticatedF8eHttpClient,
) : DemoModeF8eClient {
  override suspend fun initiateDemoMode(
    f8eEnvironment: F8eEnvironment,
    code: String,
  ): Result<EmptyResponseBody, Error> {
    return f8eHttpClient.unauthenticated()
      .bodyResult<EmptyResponseBody> {
        post("/api/demo/initiate") {
          withEnvironment(f8eEnvironment)
          setRedactedBody(
            InitiateDemoModeRequest(
              code = code
            )
          )
        }
      }.mapError { Error("Unable to validate code for demo mode") }
  }
}

@Serializable
private data class InitiateDemoModeRequest(
  @Unredacted
  @SerialName("code")
  val code: String,
) : RedactedRequestBody
