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
      minted = (
        ClientId.from(Entropy.hex(idRaw)).leftMap(RegistrationService.failure),
        secretOf(registration, Entropy.hex(secretRaw))
      ).mapN((_, _))
      result <- minted.fold(
        error => Monad[F].pure(Left(error): Either[OAuth2Error, ClientRegistrationResponse]),
        { case (id, secret) =>
          clients
            .save(
              Client(
                id,
                registration.redirectUris,
                registration.scopes,
                registration.authMethod,
                secret.map(ClientSecretHash.of),
                Jwks.empty
              )
            )
            .as(Right(ClientRegistrationResponse(id, secret, registration)): Either[OAuth2Error, ClientRegistrationResponse])
        }
      )
    } yield result

  private def secretOf(
      registration: ClientRegistration,
      raw: String
  ): Either[OAuth2Error, Option[ClientSecret]] =
    if (registration.authMethod == ClientAuthMethod.None) Right(None)
    else ClientSecret.from(raw).map(secret => Some(secret): Option[ClientSecret]).leftMap(RegistrationService.failure)
}

object RegistrationService {

  val IdEntropyBytes: Int = 16

  val SecretEntropyBytes: Int = 32

  private def failure(failure: dev.oauth2.core.ParseFailure): OAuth2Error =
    OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
}
