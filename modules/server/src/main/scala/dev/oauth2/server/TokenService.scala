package dev.oauth2.server

import cats.Monad
import cats.syntax.all._

import dev.oauth2.core.AccessToken
import dev.oauth2.core.Clock
import dev.oauth2.core.Entropy
import dev.oauth2.core.GrantId
import dev.oauth2.core.Lifetime
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.TokenRequest
import dev.oauth2.core.TokenType
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.CodeStore
import dev.oauth2.store.Grant
import dev.oauth2.store.GrantStore
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
  ): F[Either[OAuth2Error, TokenRecord]] =
    codes.consume(request.code).flatMap {
      case None => Monad[F].pure(Left(TokenService.rejected))
      case Some(record) =>
        check(record, request, client).fold(
          error => Monad[F].pure(Left(error)),
          _ => issue(record, client)
        )
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

  private def issue(record: CodeRecord, client: Client): F[Either[OAuth2Error, TokenRecord]] =
    for {
      now <- clock.instant
      grant <- entropy.bytes(TokenService.TokenEntropyBytes)
      access <- entropy.bytes(TokenService.TokenEntropyBytes)
      refresh <- entropy.bytes(TokenService.TokenEntropyBytes)
      issued = (
        GrantId.from(Entropy.hex(grant)).leftMap(TokenService.failure),
        AccessToken.from(Entropy.hex(access)).leftMap(TokenService.failure),
        if (client.confidential)
          RefreshToken.from(Entropy.hex(refresh)).map(Some(_)).leftMap(TokenService.failure)
        else Right(None): Either[OAuth2Error, Option[RefreshToken]]
      ).mapN((_, _, _))
      result <- issued.fold(
        error => Monad[F].pure(Left(error)),
        { case (grantId, accessToken, refreshToken) =>
          val minted = TokenRecord(
            accessToken = accessToken,
            refreshToken = refreshToken,
            grantId = grantId,
            clientId = record.clientId,
            subject = record.subject,
            scopes = record.scopes,
            details = record.details,
            issuedAt = now,
            accessExpiresAt = Lifetime.expiresAt(now, LifetimePolicy.of(policy, TokenType.Access)),
            refreshExpiresAt = refreshToken.map(_ => Lifetime.expiresAt(now, LifetimePolicy.of(policy, TokenType.Refresh)))
          )
          grants
            .save(Grant(grantId, record.clientId, record.subject, record.scopes, record.details, revoked = false))
            .flatMap(_ => tokens.save(minted).as(Right(minted)))
        }
      )
    } yield result
}

object TokenService {
  val TokenEntropyBytes: Int = 32

  private val rejected: OAuth2Error = OAuth2Error.InvalidGrant()

  private def failure(failure: dev.oauth2.core.ParseFailure): OAuth2Error =
    OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
}
