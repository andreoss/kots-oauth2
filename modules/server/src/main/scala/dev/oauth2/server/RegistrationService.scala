package dev.oauth2.server

import cats.Monad
import cats.syntax.all._

import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientRegistration
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Entropy
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.RegistrationToken
import dev.oauth2.core.RegistrationTokenHash
import dev.oauth2.http.ClientRegistrationResponse
import dev.oauth2.jose.Jwks
import dev.oauth2.store.Client
import dev.oauth2.store.ClientStore

final class RegistrationService[F[_]: Monad](
    clients: ClientStore[F],
    entropy: Entropy[F]
) {

  def register(registration: ClientRegistration): F[Either[OAuth2Error, ClientRegistrationResponse]] =
    for {
      idRaw <- entropy.bytes(RegistrationService.IdEntropyBytes)
      secretRaw <- entropy.bytes(RegistrationService.SecretEntropyBytes)
      tokenRaw <- entropy.bytes(RegistrationService.SecretEntropyBytes)
      minted = (
        ClientId.from(Entropy.hex(idRaw)).leftMap(RegistrationService.failure),
        secretOf(registration, Entropy.hex(secretRaw)),
        RegistrationToken.from(Entropy.hex(tokenRaw)).leftMap(RegistrationService.failure)
      ).mapN((_, _, _))
      result <- minted.fold(
        error => Monad[F].pure(Left(error): Either[OAuth2Error, ClientRegistrationResponse]),
        { case (id, secret, token) =>
          clients
            .save(
              Client(
                id,
                registration.redirectUris,
                registration.scopes,
                registration.authMethod,
                secret.map(ClientSecretHash.of),
                Jwks.empty,
                Some(RegistrationTokenHash.of(token)),
                secret.filter(_ => registration.authMethod == ClientAuthMethod.ClientSecretJwt)
              )
            )
            .as(
              Right(
                ClientRegistrationResponse(id, secret, registration, Some(token))
              ): Either[OAuth2Error, ClientRegistrationResponse]
            )
        }
      )
    } yield result

  def read(clientId: String, token: Option[String]): F[Either[OAuth2Error, ClientRegistrationResponse]] =
    authorized(clientId, token).map(_.map(RegistrationService.metadata))

  def update(
      clientId: String,
      token: Option[String],
      registration: ClientRegistration
  ): F[Either[OAuth2Error, ClientRegistrationResponse]] =
    authorized(clientId, token).flatMap {
      case Left(error)   => Monad[F].pure(Left(error): Either[OAuth2Error, ClientRegistrationResponse])
      case Right(client) =>
        val changed = client.copy(
          redirectUris = registration.redirectUris,
          scopes = registration.scopes,
          authMethod = registration.authMethod
        )
        clients
          .save(changed)
          .as(Right(RegistrationService.metadata(changed)): Either[OAuth2Error, ClientRegistrationResponse])
    }

  def remove(clientId: String, token: Option[String]): F[Either[OAuth2Error, Unit]] =
    authorized(clientId, token).flatMap {
      case Left(error)   => Monad[F].pure(Left(error): Either[OAuth2Error, Unit])
      case Right(client) => clients.delete(client.id).as(Right(()): Either[OAuth2Error, Unit])
    }

  private def authorized(clientId: String, token: Option[String]): F[Either[OAuth2Error, Client]] =
    (
      ClientId.from(clientId).leftMap(_ => RegistrationService.rejected),
      token
        .toRight(RegistrationService.rejected)
        .flatMap(raw => RegistrationToken.from(raw).leftMap(_ => RegistrationService.rejected))
    ).mapN((_, _)) match {
      case Left(error)            => Monad[F].pure(Left(error): Either[OAuth2Error, Client])
      case Right((id, candidate)) =>
        clients.find(id).map {
          case Some(client)
              if client.registrationTokenHash.exists(hash => RegistrationTokenHash.verify(hash, candidate)) =>
            Right(client): Either[OAuth2Error, Client]
          case _ => Left(RegistrationService.rejected)
        }
    }

  private def secretOf(
      registration: ClientRegistration,
      raw: String
  ): Either[OAuth2Error, Option[ClientSecret]] =
    if (registration.authMethod == ClientAuthMethod.None) Right(None)
    else
      ClientSecret
        .from(raw)
        .map(secret => Some(secret): Option[ClientSecret])
        .leftMap(RegistrationService.failure)
}

object RegistrationService {

  val IdEntropyBytes: Int = 16

  val SecretEntropyBytes: Int = 32

  private val rejected: OAuth2Error = OAuth2Error.InvalidClient()

  private def metadata(client: Client): ClientRegistrationResponse =
    ClientRegistrationResponse(
      client.id,
      None,
      ClientRegistration(client.redirectUris, client.authMethod, client.scopes),
      None
    )

  private def failure(failure: dev.oauth2.core.ParseFailure): OAuth2Error =
    OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
}
