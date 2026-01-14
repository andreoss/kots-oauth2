package dev.oauth2.server

import cats.Monad
import cats.syntax.all._
import java.time.Instant

import dev.oauth2.core.AccessToken
import dev.oauth2.core.AccessTokenHash
import dev.oauth2.core.Audience
import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientId
import dev.oauth2.core.Clock
import dev.oauth2.core.Entropy
import dev.oauth2.core.GrantId
import dev.oauth2.core.Issuer
import dev.oauth2.core.JwtId
import dev.oauth2.core.Lifetime
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.ResourceIndicator
import dev.oauth2.core.RefreshTokenHash
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TokenRequest
import dev.oauth2.core.TokenType
import dev.oauth2.jose.Jwt
import dev.oauth2.jose.JwtClaims
import dev.oauth2.jose.SigningKey
import dev.oauth2.store.AuditEvent
import dev.oauth2.store.AuditLog
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.CodeStore
import dev.oauth2.store.DeviceStore
import dev.oauth2.store.Grant
import dev.oauth2.store.GrantStore
import dev.oauth2.store.IssuedToken
import dev.oauth2.store.TokenRecord
import dev.oauth2.store.TokenStore

final class TokenService[F[_]: Monad](
    codes: CodeStore[F],
    tokens: TokenStore[F],
    grants: GrantStore[F],
    devices: DeviceStore[F],
    clock: Clock[F],
    entropy: Entropy[F],
    policy: LifetimePolicy,
    signer: Option[TokenService.Signing] = None,
    audit: Option[AuditLog[F]] = None
) {

  private val auditLog: AuditLog[F] = audit.getOrElse(AuditLog.noop[F])

  def authorizationCode(
      request: TokenRequest.Code,
      client: Client
  ): F[Either[OAuth2Error, IssuedToken]] =
    codes.consume(request.code).flatMap {
      case None       => replay(request.code)
      case Some(record) =>
        check(record, request, client).fold(
          error => Monad[F].pure(Left(error)),
          _ => issue(record, request.resource.orElse(record.resource), client)
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
            (
              Subject.from(client.id.value).leftMap(TokenService.failure),
              bound(request.resource)
            ).mapN((_, _)) match {
              case Left(error) => Monad[F].pure(Left(error))
              case Right((owner, audience)) =>
                issue(
                  TokenService.Mint(
                    None,
                    now,
                    client.id,
                    owner,
                    requested.getOrElse(client.scopes),
                    AuthorizationDetails.empty,
                    None,
                    audience
                  )
                )
            }
          )
      }

  def deviceCode(request: TokenRequest.Device, client: Client): F[Either[OAuth2Error, IssuedToken]] =
    devices.poll(request.deviceCode).flatMap {
      case None => Monad[F].pure(Left(TokenService.rejected))
      case Some(record) =>
        clock.instant.flatMap { now =>
          if (record.clientId != client.id) Monad[F].pure(Left(TokenService.rejected))
          else if (record.isExpired(now)) Monad[F].pure(Left(OAuth2Error.ExpiredToken(): OAuth2Error))
          else if (record.denied) Monad[F].pure(Left(OAuth2Error.AccessDenied(): OAuth2Error))
          else
            record.subject match {
              case None =>
                val early = record.lastPolledAt.exists(previous =>
                  now.isBefore(previous.plusSeconds(DeviceAuthorizationService.Interval.seconds))
                )
                Monad[F].pure(
                  Left(
                    if (early) OAuth2Error.SlowDown(): OAuth2Error
                    else OAuth2Error.AuthorizationPending(): OAuth2Error
                  )
                )
              case Some(subject) =>
                devices.consume(request.deviceCode).flatMap {
                  case None => Monad[F].pure(Left(TokenService.rejected))
                  case Some(_) =>
                    val refreshExpiresAt =
                      if (client.confidential)
                        Some(Lifetime.expiresAt(now, LifetimePolicy.of(policy, TokenType.Refresh)))
                      else None
                    bound(request.resource.orElse(record.resource)) match {
                      case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, IssuedToken])
                      case Right(audience) =>
                        issue(
                          TokenService.Mint(
                            None,
                            now,
                            record.clientId,
                            subject,
                            record.scopes,
                            AuthorizationDetails.empty,
                            refreshExpiresAt,
                            audience
                          )
                        )
                    }
                }
            }
        }
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
              bound(request.resource) match {
                case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, IssuedToken])
                case Right(narrowed) =>
                  issue(
                    TokenService.Mint(
                      Some(record.grantId),
                      now,
                      record.clientId,
                      record.subject,
                      requested.getOrElse(record.scopes),
                      record.details,
                      record.refreshExpiresAt,
                      narrowed.orElse(record.audience)
                    )
                  ).flatMap {
                    case Right(issued) => tokens.retire(request.refreshToken, record.grantId).as(Right(issued))
                    case left          => Monad[F].pure(left)
                  }
              }
            }
        }
      case _ => Monad[F].pure(Left(TokenService.rejected))
    }

  private def issue(
      record: CodeRecord,
      resource: Option[ResourceIndicator],
      client: Client
  ): F[Either[OAuth2Error, IssuedToken]] =
    clock.instant.flatMap { now =>
      val refreshExpiresAt =
        if (client.confidential) Some(Lifetime.expiresAt(now, LifetimePolicy.of(policy, TokenType.Refresh)))
        else None
      bound(resource) match {
        case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, IssuedToken])
        case Right(audience) =>
          issue(
            TokenService.Mint(
              None,
              now,
              record.clientId,
              record.subject,
              record.scopes,
              record.details,
              refreshExpiresAt,
              audience
            )
          ).flatMap {
            case Right(issued) => codes.redeem(record.code, issued.record.grantId).as(Right(issued))
            case left          => Monad[F].pure(left)
          }
      }
    }

  def exchange(request: TokenRequest.Exchange, client: Client): F[Either[OAuth2Error, IssuedToken]] =
    bearer(request.subjectToken, client).flatMap {
      case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, IssuedToken])
      case Right(subjectRecord) =>
        actorOf(request.actorToken, client).flatMap {
          case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, IssuedToken])
          case Right(actor) =>
            request.scope match {
              case Some(scopes) if !Scopes.isSubsetOf(scopes, subjectRecord.scopes) =>
                Monad[F].pure(Left(OAuth2Error.InvalidScope(): OAuth2Error))
              case requested =>
                audienceOf(request) match {
                  case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, IssuedToken])
                  case Right(audience) =>
                    clock.instant.flatMap { now =>
                      issue(
                        TokenService.Mint(
                          None,
                          now,
                          client.id,
                          subjectRecord.subject,
                          requested.getOrElse(subjectRecord.scopes),
                          subjectRecord.details,
                          None,
                          audience,
                          actor
                        )
                      )
                    }
                }
            }
        }
    }

  private def bearer(token: AccessToken, client: Client): F[Either[OAuth2Error, TokenRecord]] =
    tokens.findByAccess(token).flatMap {
      case Some(record) if record.clientId == client.id =>
        grants.find(record.grantId).map {
          case Some(grant) if !grant.revoked => Right(record): Either[OAuth2Error, TokenRecord]
          case _                             => Left(TokenService.rejected)
        }
      case _ => Monad[F].pure(Left(TokenService.rejected): Either[OAuth2Error, TokenRecord])
    }

  private def actorOf(
      token: Option[AccessToken],
      client: Client
  ): F[Either[OAuth2Error, Option[Subject]]] =
    token match {
      case None        => Monad[F].pure(Right(None): Either[OAuth2Error, Option[Subject]])
      case Some(value) => bearer(value, client).map(_.map(record => Some(record.subject)))
    }

  private def audienceOf(request: TokenRequest.Exchange): Either[OAuth2Error, Option[Audience]] =
    request.audience match {
      case some @ Some(_) => Right(some)
      case None           => bound(request.resource)
    }

  private def bound(resource: Option[ResourceIndicator]): Either[OAuth2Error, Option[Audience]] =
    resource match {
      case None => Right(None)
      case Some(value) =>
        Audience.from(value.value).map(Some(_): Option[Audience]).leftMap(TokenService.failure)
    }

  private def issue(mint: TokenService.Mint): F[Either[OAuth2Error, IssuedToken]] = {
    val accessExpiresAt = Lifetime.expiresAt(mint.now, LifetimePolicy.of(policy, TokenType.Access))
    for {
      grant <- grantIdOf(mint)
      access <- entropy.bytes(TokenService.TokenEntropyBytes)
      refresh <- entropy.bytes(TokenService.TokenEntropyBytes)
      issued = (
        grant,
        accessTokenOf(mint, Entropy.hex(access), accessExpiresAt),
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
            accessExpiresAt = accessExpiresAt,
            refreshExpiresAt = refreshToken.map(_ => mint.refreshExpiresAt.getOrElse(mint.now)),
            audience = mint.audience,
            actor = mint.actor
          )
          val event =
            if (mint.grantId.isEmpty) AuditEvent.Issued(mint.clientId, mint.subject, grantId)
            else AuditEvent.Refreshed(mint.clientId, mint.subject, grantId)
          grants
            .save(Grant(grantId, mint.clientId, mint.subject, mint.scopes, mint.details, revoked = false))
            .flatMap(_ => tokens.save(minted))
            .flatMap(_ => auditLog.record(event))
            .as(Right(IssuedToken(accessToken, refreshToken, minted)))
        }
      )
    } yield result
  }

  private def accessTokenOf(
      mint: TokenService.Mint,
      seed: String,
      expiresAt: Instant
  ): Either[OAuth2Error, AccessToken] =
    signer match {
      case None => AccessToken.from(seed).leftMap(TokenService.failure)
      case Some(signing) =>
        (for {
          tokenId <- JwtId.from(seed)
          compact <- Jwt.issue(
            signing.key,
            JwtClaims(
              issuer = signing.issuer,
              subject = mint.subject,
              audience = mint.audience,
              clientId = mint.clientId,
              scopes = mint.scopes,
              issuedAt = mint.now,
              expiresAt = expiresAt,
              tokenId = tokenId
            )
          )
          token <- AccessToken.from(compact)
        } yield token).leftMap(TokenService.failure)
    }

  private def grantIdOf(mint: TokenService.Mint): F[Either[OAuth2Error, GrantId]] =
    mint.grantId.fold(
      entropy
        .bytes(TokenService.TokenEntropyBytes)
        .map(raw => GrantId.from(Entropy.hex(raw)).leftMap(TokenService.failure))
    )(grantId => Monad[F].pure(Right(grantId): Either[OAuth2Error, GrantId]))
}

object TokenService {
  val TokenEntropyBytes: Int = 32

  final case class Signing(issuer: Issuer, key: SigningKey)

  private[server] final case class Mint(
      grantId: Option[GrantId],
      now: Instant,
      clientId: ClientId,
      subject: Subject,
      scopes: Scopes,
      details: AuthorizationDetails,
      refreshExpiresAt: Option[Instant],
      audience: Option[Audience] = None,
      actor: Option[Subject] = None
  )

  private val rejected: OAuth2Error = OAuth2Error.InvalidGrant()

  private def failure(failure: dev.oauth2.core.ParseFailure): OAuth2Error =
    OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
}
