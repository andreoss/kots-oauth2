package kots.oauth2.server

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.ClientAssertion
import kots.oauth2.core.ClientAuthInput
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.Clock
import kots.oauth2.core.Issuer
import kots.oauth2.core.JwtId
import kots.oauth2.core.OAuth2Error
import kots.oauth2.jose.Jws
import kots.oauth2.store.Client
import kots.oauth2.store.ClientStore
import kots.oauth2.store.ReplayStore

trait ClientAuthentication[F[_]] {
  def authenticate(input: ClientAuthInput): F[Either[OAuth2Error, Client]]
}

final class RegisteredClientAuthentication[F[_]: Monad](
    clients: ClientStore[F],
    assertions: Option[RegisteredClientAuthentication.Assertions[F]] = None,
    audit: Option[kots.oauth2.store.AuditLog[F]] = None
) extends ClientAuthentication[F] {

  private val auditLog: kots.oauth2.store.AuditLog[F] =
    audit.getOrElse(kots.oauth2.store.AuditLog.noop[F])

  def authenticate(input: ClientAuthInput): F[Either[OAuth2Error, Client]] =
    resolved(input).flatMap {
      case left @ Left(_) =>
        auditLog
          .record(kots.oauth2.store.AuditEvent.AuthenticationFailed(input.subject))
          .as(left: Either[OAuth2Error, Client])
      case right => Monad[F].pure(right)
    }

  private def resolved(input: ClientAuthInput): F[Either[OAuth2Error, Client]] =
    input.assertion match {
      case Some(raw) if input.basic.isEmpty && input.clientSecret.isEmpty => asserted(raw, input)
      case Some(_) => Monad[F].pure(Left(RegisteredClientAuthentication.rejected))
      case None    =>
        input.subject match {
          case None     => Monad[F].pure(Left(RegisteredClientAuthentication.rejected))
          case Some(id) =>
            clients.find(id).map {
              case None         => Left(RegisteredClientAuthentication.rejected)
              case Some(client) => check(client, input)
            }
        }
    }

  private def asserted(raw: ClientAssertion, input: ClientAuthInput): F[Either[OAuth2Error, Client]] =
    assertions match {
      case None         => Monad[F].pure(Left(RegisteredClientAuthentication.rejected))
      case Some(config) =>
        unverified(raw) match {
          case Left(error)                                           => Monad[F].pure(Left(error))
          case Right(claimed) if input.clientId.exists(_ != claimed) =>
            Monad[F].pure(Left(RegisteredClientAuthentication.rejected))
          case Right(claimed) =>
            clients.find(claimed).flatMap {
              case Some(client) if RegisteredClientAuthentication.asserts(client.authMethod) =>
                config.clock.instant.flatMap { now =>
                  verified(raw, client, config, now) match {
                    case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, Client])
                    case Right(seen) =>
                      config.replays.record(seen.tokenId, seen.expiresAt).map {
                        case true  => Right(client): Either[OAuth2Error, Client]
                        case false => Left(RegisteredClientAuthentication.rejected)
                      }
                  }
                }
              case _ =>
                Monad[F].pure(Left(RegisteredClientAuthentication.rejected): Either[OAuth2Error, Client])
            }
        }
    }

  private def unverified(raw: ClientAssertion): Either[OAuth2Error, ClientId] =
    raw.value.split('.') match {
      case Array(_, payload, _) =>
        for {
          decoded <- decode(payload)
          json <- io.circe.parser
            .parse(new String(decoded, StandardCharsets.UTF_8))
            .left
            .map(_ => RegisteredClientAuthentication.rejected)
          sub <- json.hcursor.get[String]("sub").left.map(_ => RegisteredClientAuthentication.rejected)
          id <- ClientId.from(sub).left.map(_ => RegisteredClientAuthentication.rejected)
        } yield id
      case _ => Left(RegisteredClientAuthentication.rejected)
    }

  private def verified(
      raw: ClientAssertion,
      client: Client,
      config: RegisteredClientAuthentication.Assertions[F],
      now: Instant
  ): Either[OAuth2Error, RegisteredClientAuthentication.Asserted] =
    for {
      payload <- payloadOf(raw, client)
      json <- io.circe.parser.parse(payload).left.map(_ => RegisteredClientAuthentication.rejected)
      cursor = json.hcursor
      iss <- claim(cursor, "iss")
      sub <- claim(cursor, "sub")
      aud <- claim(cursor, "aud")
      exp <- cursor.get[Long]("exp").left.map(_ => RegisteredClientAuthentication.rejected)
      jti <- claim(cursor, "jti").flatMap(value =>
        JwtId.from(value).left.map(_ => RegisteredClientAuthentication.rejected)
      )
      _ <- refuse(iss == client.id.value && sub == client.id.value)
      _ <- refuse(aud == config.audience.value)
      expiresAt = Instant.ofEpochSecond(exp)
      _ <- refuse(now.isBefore(expiresAt))
    } yield RegisteredClientAuthentication.Asserted(jti, expiresAt)

  private def payloadOf(raw: ClientAssertion, client: Client): Either[OAuth2Error, String] =
    client.authMethod match {
      case ClientAuthMethod.ClientSecretJwt =>
        client.secret
          .toRight(RegisteredClientAuthentication.rejected)
          .flatMap(shared =>
            kots.oauth2.jose.Hs256
              .verify(raw.value, shared)
              .left
              .map(_ => RegisteredClientAuthentication.rejected)
          )
      case _ =>
        Jws.verify(raw.value, client.keys).left.map(_ => RegisteredClientAuthentication.rejected)
    }

  private def claim(cursor: io.circe.HCursor, name: String): Either[OAuth2Error, String] =
    cursor.get[String](name).left.map(_ => RegisteredClientAuthentication.rejected)

  private def refuse(holds: Boolean): Either[OAuth2Error, Unit] =
    Either.cond(holds, (), RegisteredClientAuthentication.rejected)

  private def decode(raw: String): Either[OAuth2Error, Array[Byte]] =
    try Right(Base64.getUrlDecoder.decode(raw))
    catch { case _: IllegalArgumentException => Left(RegisteredClientAuthentication.rejected) }

  private def check(client: Client, input: ClientAuthInput): Either[OAuth2Error, Client] =
    if (input.clientId.exists(_ != client.id)) Left(RegisteredClientAuthentication.rejected)
    else
      client.authMethod match {
        case ClientAuthMethod.None =>
          Either.cond(
            input.basic.isEmpty && input.clientSecret.isEmpty,
            client,
            RegisteredClientAuthentication.rejected
          )
        case ClientAuthMethod.ClientSecretBasic =>
          input.basic match {
            case Some(credentials) => secret(client, credentials.secret)
            case None              => Left(RegisteredClientAuthentication.rejected)
          }
        case ClientAuthMethod.ClientSecretPost =>
          input.clientSecret match {
            case Some(candidate) => secret(client, candidate)
            case None            => Left(RegisteredClientAuthentication.rejected)
          }
        case ClientAuthMethod.PrivateKeyJwt | ClientAuthMethod.ClientSecretJwt =>
          Left(RegisteredClientAuthentication.rejected)
      }

  private def secret(client: Client, candidate: ClientSecret): Either[OAuth2Error, Client] =
    client.secretHash match {
      case Some(hash) =>
        Either.cond(
          ClientSecretHash.verify(hash, candidate),
          client,
          RegisteredClientAuthentication.rejected
        )
      case None => Left(RegisteredClientAuthentication.rejected)
    }
}

object RegisteredClientAuthentication {

  final case class Assertions[F[_]](audience: Issuer, replays: ReplayStore[F], clock: Clock[F])

  private[server] def asserts(method: ClientAuthMethod): Boolean =
    method == ClientAuthMethod.PrivateKeyJwt || method == ClientAuthMethod.ClientSecretJwt

  private[server] final case class Asserted(tokenId: JwtId, expiresAt: Instant)

  private val rejected: OAuth2Error = OAuth2Error.InvalidClient()
}
