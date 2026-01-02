package dev.oauth2.store

import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientId
import dev.oauth2.core.GrantId
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject

final case class Grant(
    id: GrantId,
    clientId: ClientId,
    subject: Subject,
    scopes: Scopes,
    details: AuthorizationDetails,
    revoked: Boolean
)

trait GrantStore[F[_]] {
  def save(grant: Grant): F[Unit]

  def find(id: GrantId): F[Option[Grant]]

  def revoke(id: GrantId): F[Unit]
}
