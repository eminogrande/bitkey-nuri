package build.wallet.f8e.relationships.models

import build.wallet.bitkey.relationships.ProtectedCustomerEnrollmentPakeKey
import build.wallet.bitkey.relationships.TrustedContactRole
import build.wallet.crypto.PublicKey
import build.wallet.ktor.result.RedactedResponseBody
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class RetrieveTrustedContactInvitationResponseBody(
  val invitation: RetrieveTrustedContactInvitation,
) : RedactedResponseBody

@Serializable
internal data class RetrieveTrustedContactInvitation(
  @SerialName("expires_at")
  val expiresAt: Instant,
  @SerialName("recovery_relationship_id")
  val relationshipId: String,
  @SerialName("protected_customer_enrollment_pake_pubkey")
  val protectedCustomerEnrollmentPakePubkey: PublicKey<ProtectedCustomerEnrollmentPakeKey>,
  @SerialName("recovery_relationship_roles")
  val recoveryRelationshipRoles: Set<TrustedContactRole>,
)
