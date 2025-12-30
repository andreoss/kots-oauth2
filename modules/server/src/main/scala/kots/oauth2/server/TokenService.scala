package kots.oauth2.server

import cats.Monad
import cats.syntax.all._
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

import kots.oauth2.core.AccessToken
import kots.oauth2.core.AccessTokenHash
import kots.oauth2.core.Audience
import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.Entropy
import kots.oauth2.core.GrantId
import kots.oauth2.core.IdentityAssertion
import kots.oauth2.core.Issuer
import kots.oauth2.core.JwtId
import kots.oauth2.core.KeyThumbprint
import kots.oauth2.core.Lifetime
import kots.oauth2.core.LifetimePolicy
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.Pkce
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.RefreshTokenHash
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.TokenRequest
import kots.oauth2.core.TokenType
import kots.oauth2.jose.Jwt
import kots.oauth2.jose.JwtClaims
import kots.oauth2.jose.SigningKey
import kots.oauth2.store.AuditEvent
import kots.oauth2.store.AuditLog
import kots.oauth2.store.Client
import kots.oauth2.store.CodeRecord
import kots.oauth2.store.CodeStore
import kots.oauth2.store.DeviceStore
import kots.oauth2.store.Grant
import kots.oauth2.store.GrantStore
import kots.oauth2.store.IssuedToken
import kots.oauth2.store.ReplayStore
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.TokenStore

final class TokenService[F[_]: Monad](
    codes: CodeStore[F],
    tokens: TokenStore[F],
    grants: GrantStore[F],
    devices: DeviceStore[F],
    clock: Clock[F],
    entropy: Entropy[F],
    policy: LifetimePolicy,
    signer: Option[TokenService.Signing] = None,
    audit: Option[AuditLog[F]] = None,
    identityAssertions: Option[TokenService.IdentityAssertions[F]] = None
) {

  private val auditLog: AuditLog[F] = audit.getOrElse(AuditLog.noop[F])

  def authorizationCode(
      request: TokenRequest.Code,
      client: Client,
      jkt: Option[KeyThumbprint] = None,
      x5t: Option[CertificateThumbprint] = None
  ): F[Either[OAuth2Error, IssuedToken]] =
    codes.consume(request.code).flatMap {
      case None         => replay(request.code)
      case Some(record) =>
        check(record, request, client).fold(
          error => error.asLeft.pure[F],
          _ => issue(record, request.resource.orElse(record.resource), client, jkt, x5t)
        )
    }

  def refresh(
      request: TokenRequest.Refresh,
      client: Client,
      jkt: Option[KeyThumbprint] = None,
      x5t: Option[CertificateThumbprint] = None
  ): F[Either[OAuth2Error, IssuedToken]] =
    tokens.findByRefresh(request.refreshToken).flatMap {
      case None         => reuse(request.refreshToken)
      case Some(record) => rotate(record, request, client, jkt, x5t)
    }

  def clientCredentials(
      request: TokenRequest.ClientCredentials,
      client: Client,
      jkt: Option[KeyThumbprint] = None,
      x5t: Option[CertificateThumbprint] = None
  ): F[Either[OAuth2Error, IssuedToken]] =
    if (!client.confidential) (OAuth2Error.UnauthorizedClient(): OAuth2Error).asLeft.pure[F]
    else
      request.scope match {
        case Some(scopes) if !client.allowsScopes(scopes) =>
          (OAuth2Error.InvalidScope(): OAuth2Error).asLeft.pure[F]
        case requested =>
          clock.instant.flatMap(now =>
            (
              Subject.from(client.id.value).leftMap(TokenService.failure),
              bound(request.resource)
            ).mapN((_, _)) match {
              case Left(error)              => error.asLeft.pure[F]
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
                    audience,
                    jkt = jkt,
                    x5t = x5t
                  )
                )
            }
          )
      }

  def deviceCode(
      request: TokenRequest.Device,
      client: Client,
      jkt: Option[KeyThumbprint] = None,
      x5t: Option[CertificateThumbprint] = None
  ): F[Either[OAuth2Error, IssuedToken]] =
    devices.poll(request.deviceCode).flatMap {
      case None         => TokenService.rejected.asLeft.pure[F]
      case Some(record) =>
        clock.instant.flatMap { now =>
          if (record.clientId != client.id) TokenService.rejected.asLeft.pure[F]
          else if (record.isExpired(now)) (OAuth2Error.ExpiredToken(): OAuth2Error).asLeft.pure[F]
          else if (record.denied) (OAuth2Error.AccessDenied(): OAuth2Error).asLeft.pure[F]
          else
            record.subject match {
              case None =>
                val early = record.lastPolledAt.exists(previous =>
                  now.isBefore(previous.plusSeconds(DeviceAuthorizationService.Interval.seconds))
                )
                val refusal: OAuth2Error =
                  if (early) OAuth2Error.SlowDown() else OAuth2Error.AuthorizationPending()
                refusal.asLeft.pure[F]
              case Some(subject) =>
                devices.consume(request.deviceCode).flatMap {
                  case None    => TokenService.rejected.asLeft.pure[F]
                  case Some(_) =>
                    val refreshExpiresAt =
                      if (client.confidential)
                        Some(Lifetime.expiresAt(now, LifetimePolicy.of(policy, TokenType.Refresh)))
                      else None
                    bound(request.resource.orElse(record.resource)) match {
                      case Left(error)     => error.asLeft[IssuedToken].pure[F]
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
                            audience,
                            jkt = jkt,
                            x5t = x5t
                          )
                        )
                    }
                }
            }
        }
    }

  def idJag(
      request: TokenRequest.IdJag,
      client: Client,
      jkt: Option[KeyThumbprint] = None,
      x5t: Option[CertificateThumbprint] = None
  ): F[Either[OAuth2Error, IssuedToken]] =
    identityAssertions match {
      case None         => TokenService.rejected.asLeft[IssuedToken].pure[F]
      case Some(config) =>
        config.clock.instant.flatMap(now => asserted(request, client, config, now, jkt, x5t))
    }

  private def asserted(
      request: TokenRequest.IdJag,
      client: Client,
      config: TokenService.IdentityAssertions[F],
      now: Instant,
      jkt: Option[KeyThumbprint],
      x5t: Option[CertificateThumbprint]
  ): F[Either[OAuth2Error, IssuedToken]] =
    issuerOf(request.assertion) match {
      case Left(error)   => error.asLeft[IssuedToken].pure[F]
      case Right(issuer) =>
        config.assertionIssuers.keys(issuer).flatMap {
          case None       => TokenService.rejected.asLeft[IssuedToken].pure[F]
          case Some(keys) =>
            verified(request.assertion, keys, config, now) match {
              case Left(error)   => error.asLeft[IssuedToken].pure[F]
              case Right(claims) =>
                if (!claims.audience.exists(_.value == config.issuer.value))
                  TokenService.rejected.asLeft[IssuedToken].pure[F]
                else if (claims.clientId != client.id)
                  TokenService.rejected.asLeft[IssuedToken].pure[F]
                else
                  config.replays.record(claims.tokenId, claims.expiresAt).flatMap {
                    case false =>
                      auditLog
                        .record(AuditEvent.AuthenticationFailed(Some(client.id)))
                        .as(TokenService.rejected.asLeft[IssuedToken]: Either[OAuth2Error, IssuedToken])
                    case true =>
                      replayed(request, client, claims, now, jkt, x5t)
                  }
            }
        }
    }

  private def replayed(
      request: TokenRequest.IdJag,
      client: Client,
      claims: JwtClaims,
      now: Instant,
      jkt: Option[KeyThumbprint],
      x5t: Option[CertificateThumbprint]
  ): F[Either[OAuth2Error, IssuedToken]] =
    assertedMint(request, client, claims, now, jkt, x5t) match {
      case Left(error) => error.asLeft[IssuedToken].pure[F]
      case Right(mint) => issue(mint)
    }

  private def verified(
      assertion: IdentityAssertion,
      keys: kots.oauth2.jose.Jwks,
      config: TokenService.IdentityAssertions[F],
      now: Instant
  ): Either[OAuth2Error, JwtClaims] =
    Jwt
      .claims(assertion.value, keys, now, Set(Jwt.IdentityAssertionTyp), config.skew)
      .left
      .map(_ => TokenService.rejected)

  private def issuerOf(assertion: IdentityAssertion): Either[OAuth2Error, Issuer] =
    assertion.value.split('.') match {
      case Array(_, payload, _) =>
        for {
          decoded <- bytesOf(payload)
          json <- io.circe.parser
            .parse(new String(decoded, StandardCharsets.UTF_8))
            .left
            .map(_ => TokenService.rejected)
          value <- json.hcursor.get[String]("iss").left.map(_ => TokenService.rejected)
          issuer <- Issuer.from(value).left.map(_ => TokenService.rejected)
        } yield issuer
      case _ => Left(TokenService.rejected)
    }

  private def bytesOf(raw: String): Either[OAuth2Error, Array[Byte]] =
    try Right(Base64.getUrlDecoder.decode(raw))
    catch { case _: IllegalArgumentException => Left(TokenService.rejected) }

  private def assertedMint(
      request: TokenRequest.IdJag,
      client: Client,
      claims: JwtClaims,
      now: Instant,
      jkt: Option[KeyThumbprint],
      x5t: Option[CertificateThumbprint]
  ): Either[OAuth2Error, TokenService.Mint] =
    for {
      audience <- bound(request.resource)
      granted = Scopes.intersect(client.scopes, claims.scopes)
      scopes <- request.scope match {
        case None         => Right(granted)
        case Some(wanted) =>
          Either.cond(
            Scopes.isSubsetOf(wanted, granted),
            wanted,
            (OAuth2Error.InvalidScope(): OAuth2Error)
          )
      }
    } yield TokenService.Mint(
      grantId = None,
      now = now,
      clientId = client.id,
      subject = claims.subject,
      scopes = scopes,
      details = AuthorizationDetails.empty,
      refreshExpiresAt = None,
      audience = audience,
      jkt = jkt,
      x5t = x5t
    )

  private def replay(code: AuthorizationCode): F[Either[OAuth2Error, IssuedToken]] =
    codes.redeemed(code).flatMap {
      case None        => TokenService.rejected.asLeft.pure[F]
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
      case None        => TokenService.rejected.asLeft.pure[F]
      case Some(grant) => grants.revoke(grant) >> tokens.revokeGrant(grant).as(Left(TokenService.rejected))
    }

  private def rotate(
      record: TokenRecord,
      request: TokenRequest.Refresh,
      client: Client,
      jkt: Option[KeyThumbprint],
      x5t: Option[CertificateThumbprint]
  ): F[Either[OAuth2Error, IssuedToken]] =
    grants.find(record.grantId).flatMap {
      case Some(grant) if !grant.revoked && record.clientId == client.id =>
        request.scope match {
          case Some(scopes) if !Scopes.isSubsetOf(scopes, record.scopes) =>
            (OAuth2Error.InvalidScope(): OAuth2Error).asLeft.pure[F]
          case requested =>
            clock.instant.flatMap { now =>
              bound(request.resource) match {
                case Left(error)     => error.asLeft[IssuedToken].pure[F]
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
                      narrowed.orElse(record.audience),
                      jkt = jkt,
                      x5t = x5t
                    )
                  ).flatMap {
                    case Right(issued) =>
                      tokens.retire(request.refreshToken, record.grantId).as(Right(issued))
                    case left => left.pure[F]
                  }
              }
            }
        }
      case _ => TokenService.rejected.asLeft.pure[F]
    }

  private def issue(
      record: CodeRecord,
      resource: Option[ResourceIndicator],
      client: Client,
      jkt: Option[KeyThumbprint],
      x5t: Option[CertificateThumbprint]
  ): F[Either[OAuth2Error, IssuedToken]] =
    clock.instant.flatMap { now =>
      val refreshExpiresAt =
        if (client.confidential) Some(Lifetime.expiresAt(now, LifetimePolicy.of(policy, TokenType.Refresh)))
        else None
      bound(resource) match {
        case Left(error)     => error.asLeft[IssuedToken].pure[F]
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
              audience,
              jkt = jkt,
              x5t = x5t
            )
          ).flatMap {
            case Right(issued) => codes.redeem(record.code, issued.record.grantId).as(Right(issued))
            case left          => left.pure[F]
          }
      }
    }

  def exchange(
      request: TokenRequest.Exchange,
      client: Client,
      jkt: Option[KeyThumbprint] = None,
      x5t: Option[CertificateThumbprint] = None
  ): F[Either[OAuth2Error, IssuedToken]] =
    bearer(request.subjectToken, client).flatMap {
      case Left(error)          => error.asLeft[IssuedToken].pure[F]
      case Right(subjectRecord) =>
        actorOf(request.actorToken, client).flatMap {
          case Left(error)  => error.asLeft[IssuedToken].pure[F]
          case Right(actor) =>
            request.scope match {
              case Some(scopes) if !Scopes.isSubsetOf(scopes, subjectRecord.scopes) =>
                (OAuth2Error.InvalidScope(): OAuth2Error).asLeft.pure[F]
              case requested =>
                audienceOf(request) match {
                  case Left(error)     => error.asLeft[IssuedToken].pure[F]
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
                          actor,
                          jkt = jkt,
                          x5t = x5t
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
      case _ => TokenService.rejected.asLeft[TokenRecord].pure[F]
    }

  private def actorOf(
      token: Option[AccessToken],
      client: Client
  ): F[Either[OAuth2Error, Option[Subject]]] =
    token match {
      case None        => none[Subject].asRight[OAuth2Error].pure[F]
      case Some(value) => bearer(value, client).map(_.map(record => Some(record.subject)))
    }

  private def audienceOf(request: TokenRequest.Exchange): Either[OAuth2Error, Option[Audience]] =
    request.audience match {
      case some @ Some(_) => Right(some)
      case None           => bound(request.resource)
    }

  private def bound(resource: Option[ResourceIndicator]): Either[OAuth2Error, Option[Audience]] =
    resource match {
      case None        => Right(None)
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
        error => error.asLeft.pure[F],
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
      case None          => AccessToken.from(seed).leftMap(TokenService.failure)
      case Some(signing) =>
        (for {
          tokenId <- JwtId.from(seed)
          compact <- Jwt.issue(
            signing.key,
            JwtClaims(
              issuer = signing.issuer,
              subject = mint.subject,
              audience = audienceOf(signing, mint).toList,
              clientId = mint.clientId,
              scopes = mint.scopes,
              issuedAt = mint.now,
              expiresAt = expiresAt,
              tokenId = tokenId,
              acr = mint.acr,
              jkt = mint.jkt,
              x5t = mint.x5t,
              notBefore = Some(mint.now)
            )
          )
          token <- AccessToken.from(compact)
        } yield token).leftMap(TokenService.failure)
    }

  private def audienceOf(signing: TokenService.Signing, mint: TokenService.Mint): Option[Audience] =
    mint.audience
      .orElse(Audience.from(signing.issuer.value).toOption)

  private def grantIdOf(mint: TokenService.Mint): F[Either[OAuth2Error, GrantId]] =
    mint.grantId.fold(
      entropy
        .bytes(TokenService.TokenEntropyBytes)
        .map(raw => GrantId.from(Entropy.hex(raw)).leftMap(TokenService.failure))
    )(grantId => grantId.asRight[OAuth2Error].pure[F])
}

object TokenService {
  val TokenEntropyBytes: Int = 32

  final case class Signing(issuer: Issuer, key: SigningKey)

  final case class IdentityAssertions[F[_]](
      issuer: Issuer,
      assertionIssuers: AssertionIssuers[F],
      replays: ReplayStore[F],
      clock: Clock[F],
      skew: java.time.Duration = java.time.Duration.ofSeconds(60L)
  )

  private[server] final case class Mint(
      grantId: Option[GrantId],
      now: Instant,
      clientId: ClientId,
      subject: Subject,
      scopes: Scopes,
      details: AuthorizationDetails,
      refreshExpiresAt: Option[Instant],
      audience: Option[Audience] = None,
      actor: Option[Subject] = None,
      acr: Option[kots.oauth2.core.Acr] = None,
      jkt: Option[kots.oauth2.core.KeyThumbprint] = None,
      x5t: Option[CertificateThumbprint] = None
  )

  private val rejected: OAuth2Error = OAuth2Error.InvalidGrant()

  private def failure(failure: kots.oauth2.core.ParseFailure): OAuth2Error =
    OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
}
