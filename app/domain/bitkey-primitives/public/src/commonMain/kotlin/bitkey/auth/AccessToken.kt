package bitkey.auth

import dev.zacsweers.redacted.annotations.Redacted

@Redacted
data class AccessToken(
  val raw: String,
)
