package dev.oauth2.store

import java.time.Instant

import dev.oauth2.core.AccessToken
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientId
import dev.oauth2.core.GrantId
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject

final case class TokenRecord(
    accessToken: AccessToken,
    refreshToken: Option[RefreshToken],
    grantId: GrantId,
    clientId: ClientId,
    subject: Subject,
    scopes: Scopes,
    details: AuthorizationDetails,
    issuedAt: Instant,
    accessExpiresAt: Instant,
    refreshExpiresAt: Option[Instant]
) {
  def isAccessExpired(now: Instant): Boolean = !now.isBefore(accessExpiresAt)

  def isRefreshExpired(now: Instant): Boolean =
    refreshExpiresAt.fold(true)(expiry => !now.isBefore(expiry))
}

trait TokenStore[F[_]] {
  def save(record: TokenRecord): F[Unit]

  def findByAccess(token: AccessToken): F[Option[TokenRecord]]

  def findByRefresh(token: RefreshToken): F[Option[TokenRecord]]

  def drop(refreshToken: RefreshToken): F[Unit]

  def revokeGrant(grantId: GrantId): F[Unit]
}
