package dev.oauth2.server

import cats.Monad
import cats.syntax.all._
import java.time.Instant

import dev.oauth2.core.AccessToken
import dev.oauth2.core.AccessTokenHash
import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientId
import dev.oauth2.core.Clock
import dev.oauth2.core.Entropy
import dev.oauth2.core.GrantId
import dev.oauth2.core.Lifetime
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.RefreshTokenHash
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TokenRequest
import dev.oauth2.core.TokenType
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.CodeStore
import dev.oauth2.store.Grant
import dev.oauth2.store.GrantStore
import dev.oauth2.store.IssuedToken
import dev.oauth2.store.TokenRecord
import dev.oauth2.store.TokenStore

final class TokenService[F[_]: Monad](
    codes: CodeStore[F],
    tokens: TokenStore[F],
    grants: GrantStore[F],
    clock: Clock[F],
    entropy: Entropy[F],
    policy: LifetimePolicy
) {

  def authorizationCode(
      request: TokenRequest.Code,
      client: Client
  ): F[Either[OAuth2Error, IssuedToken]] =
    codes.consume(request.code).flatMap {
      case None       => replay(request.code)
      case Some(record) =>
        check(record, request, client).fold(
          error => Monad[F].pure(Left(error)),
          _ => issue(record, client)
        )
    }

  def refresh(request: TokenRequest.Refresh, client: Client): F[Either[OAuth2Error, IssuedToken]] =
    tokens.findByRefresh(request.refreshToken).flatMap {
      case None         => reuse(request.refreshToken)
      case Some(record) => rotate(record, request, client)
    }

  def clientCredentials(
      request: TokenRequest.ClientCredentials,
      client: Client
  ): F[Either[OAuth2Error, IssuedToken]] =
    if (!client.confidential) Monad[F].pure(Left(OAuth2Error.UnauthorizedClient(): OAuth2Error))
    else
      request.scope match {
        case Some(scopes) if !client.allowsScopes(scopes) =>
          Monad[F].pure(Left(OAuth2Error.InvalidScope(): OAuth2Error))
        case requested =>
          clock.instant.flatMap(now =>
            Subject.from(client.id.value).leftMap(TokenService.failure) match {
              case Left(error) => Monad[F].pure(Left(error))
              case Right(owner) =>
                issue(
                  TokenService.Mint(
                    None,
                    now,
                    client.id,
                    owner,
                    requested.getOrElse(client.scopes),
                    AuthorizationDetails.empty,
                    None
                  )
                )
            }
          )
      }

  private def replay(code: AuthorizationCode): F[Either[OAuth2Error, IssuedToken]] =
    codes.redeemed(code).flatMap {
      case None        => Monad[F].pure(Left(TokenService.rejected))
      case Some(grant) => grants.revoke(grant) >> tokens.revokeGrant(grant).as(Left(TokenService.rejected))
    }

  private def check(
      record: CodeRecord,
      request: TokenRequest.Code,
      client: Client
  ): Either[OAuth2Error, Unit] =
    for {
      _ <- Either.cond(record.clientId == client.id, (), TokenService.rejected)
      _ <- request.redirectUri match {
        case Some(uri) =>
          Either.cond(RedirectUri.matches(Set(record.redirectUri), uri), (), TokenService.rejected)
        case None => Right(())
      }
      _ <- record.pkce match {
        case Some(pkce) => Pkce.verify(pkce, request.verifier)
        case None       => Left(TokenService.rejected)
      }
    } yield ()

  private def reuse(refreshToken: RefreshToken): F[Either[OAuth2Error, IssuedToken]] =
    tokens.rotated(refreshToken).flatMap {
      case None        => Monad[F].pure(Left(TokenService.rejected))
      case Some(grant) => grants.revoke(grant) >> tokens.revokeGrant(grant).as(Left(TokenService.rejected))
    }

  private def rotate(
      record: TokenRecord,
      request: TokenRequest.Refresh,
      client: Client
  ): F[Either[OAuth2Error, IssuedToken]] =
    grants.find(record.grantId).flatMap {
      case Some(grant) if !grant.revoked && record.clientId == client.id =>
        request.scope match {
          case Some(scopes) if !Scopes.isSubsetOf(scopes, record.scopes) =>
            Monad[F].pure(Left(OAuth2Error.InvalidScope(): OAuth2Error))
          case requested =>
            clock.instant.flatMap { now =>
              issue(
                TokenService.Mint(
                  Some(record.grantId),
                  now,
                  record.clientId,
                  record.subject,
                  requested.getOrElse(record.scopes),
                  record.details,
                  record.refreshExpiresAt
                )
              ).flatMap {
                case Right(issued) => tokens.retire(request.refreshToken, record.grantId).as(Right(issued))
                case left          => Monad[F].pure(left)
              }
            }
        }
      case _ => Monad[F].pure(Left(TokenService.rejected))
    }

  private def issue(record: CodeRecord, client: Client): F[Either[OAuth2Error, IssuedToken]] =
    clock.instant.flatMap { now =>
      val refreshExpiresAt =
        if (client.confidential) Some(Lifetime.expiresAt(now, LifetimePolicy.of(policy, TokenType.Refresh)))
        else None
      issue(TokenService.Mint(None, now, record.clientId, record.subject, record.scopes, record.details, refreshExpiresAt))
        .flatMap {
          case Right(issued) => codes.redeem(record.code, issued.record.grantId).as(Right(issued))
          case left          => Monad[F].pure(left)
        }
    }

  private def issue(mint: TokenService.Mint): F[Either[OAuth2Error, IssuedToken]] =
    for {
      grant <- grantIdOf(mint)
      access <- entropy.bytes(TokenService.TokenEntropyBytes)
      refresh <- entropy.bytes(TokenService.TokenEntropyBytes)
      issued = (
        grant,
        AccessToken.from(Entropy.hex(access)).leftMap(TokenService.failure),
        if (mint.refreshExpiresAt.isDefined)
          RefreshToken.from(Entropy.hex(refresh)).map(Some(_)).leftMap(TokenService.failure)
        else Right(None): Either[OAuth2Error, Option[RefreshToken]]
      ).mapN((_, _, _))
      result <- issued.fold(
        error => Monad[F].pure(Left(error)),
        { case (grantId, accessToken, refreshToken) =>
          val minted = TokenRecord(
            accessTokenHash = AccessTokenHash.of(accessToken),
            refreshTokenHash = refreshToken.map(RefreshTokenHash.of),
            grantId = grantId,
            clientId = mint.clientId,
            subject = mint.subject,
            scopes = mint.scopes,
            details = mint.details,
            issuedAt = mint.now,
            accessExpiresAt = Lifetime.expiresAt(mint.now, LifetimePolicy.of(policy, TokenType.Access)),
            refreshExpiresAt = refreshToken.map(_ => mint.refreshExpiresAt.getOrElse(mint.now))
          )
          grants
            .save(Grant(grantId, mint.clientId, mint.subject, mint.scopes, mint.details, revoked = false))
            .flatMap(_ => tokens.save(minted))
            .as(Right(IssuedToken(accessToken, refreshToken, minted)))
        }
      )
    } yield result

  private def grantIdOf(mint: TokenService.Mint): F[Either[OAuth2Error, GrantId]] =
    mint.grantId.fold(
      entropy
        .bytes(TokenService.TokenEntropyBytes)
        .map(raw => GrantId.from(Entropy.hex(raw)).leftMap(TokenService.failure))
    )(grantId => Monad[F].pure(Right(grantId): Either[OAuth2Error, GrantId]))
}

object TokenService {
  val TokenEntropyBytes: Int = 32

  private[server] final case class Mint(
      grantId: Option[GrantId],
      now: Instant,
      clientId: ClientId,
      subject: Subject,
      scopes: Scopes,
      details: AuthorizationDetails,
      refreshExpiresAt: Option[Instant]
  )

  private val rejected: OAuth2Error = OAuth2Error.InvalidGrant()

  private def failure(failure: dev.oauth2.core.ParseFailure): OAuth2Error =
    OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
}
