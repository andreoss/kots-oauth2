package kots.oauth2.store

import java.time.Instant

import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.Pkce
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject

final case class CodeRecord(
    code: AuthorizationCode,
    clientId: ClientId,
    redirectUri: RedirectUri,
    subject: Subject,
    scopes: Scopes,
    details: AuthorizationDetails,
    pkce: Option[Pkce],
    expiresAt: Instant,
    resource: Option[ResourceIndicator] = None
) {
  def isExpired(now: Instant): Boolean = !now.isBefore(expiresAt)
}

trait CodeStore[F[_]] {
  def save(record: CodeRecord): F[Unit]

  def consume(code: AuthorizationCode): F[Option[CodeRecord]]

  def redeem(code: AuthorizationCode, grant: GrantId): F[Unit]

  def redeemed(code: AuthorizationCode): F[Option[GrantId]]

  def sweep: F[Int]
}
