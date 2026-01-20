package kots.oauth2.store

import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject

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
