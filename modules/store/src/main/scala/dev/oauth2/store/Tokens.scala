package dev.oauth2.store

import java.time.Instant

import dev.oauth2.core.AccessToken
import dev.oauth2.core.AccessTokenHash
import dev.oauth2.core.Audience
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientId
import dev.oauth2.core.GrantId
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.RefreshTokenHash
import dev.oauth2.core.RevocationToken
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TokenTypeHint

final case class TokenRecord(
    accessTokenHash: AccessTokenHash,
    refreshTokenHash: Option[RefreshTokenHash],
    grantId: GrantId,
    clientId: ClientId,
    subject: Subject,
    scopes: Scopes,
    details: AuthorizationDetails,
    issuedAt: Instant,
    accessExpiresAt: Instant,
    refreshExpiresAt: Option[Instant],
    audience: Option[Audience] = None,
    actor: Option[Subject] = None
) {
  def isAccessExpired(now: Instant): Boolean = !now.isBefore(accessExpiresAt)

  def isRefreshExpired(now: Instant): Boolean =
    refreshExpiresAt.fold(true)(expiry => !now.isBefore(expiry))

  def matchesAccess(token: AccessToken): Boolean =
    AccessTokenHash.verify(accessTokenHash, token)

  def matchesRefresh(token: RefreshToken): Boolean =
    refreshTokenHash.exists(hash => RefreshTokenHash.verify(hash, token))
}

final case class IssuedToken(
    accessToken: AccessToken,
    refreshToken: Option[RefreshToken],
    record: TokenRecord
)

trait TokenStore[F[_]] {
  def save(record: TokenRecord): F[Unit]

  def findByAccess(token: AccessToken): F[Option[TokenRecord]]

  def findByRefresh(token: RefreshToken): F[Option[TokenRecord]]

  def drop(refreshToken: RefreshToken): F[Unit]

  def retire(refreshToken: RefreshToken, grantId: GrantId): F[Unit]

  def rotated(refreshToken: RefreshToken): F[Option[GrantId]]

  def revoke(token: RevocationToken, hint: Option[TokenTypeHint], clientId: ClientId): F[Option[GrantId]]

  def revokeGrant(grantId: GrantId): F[Unit]
}
