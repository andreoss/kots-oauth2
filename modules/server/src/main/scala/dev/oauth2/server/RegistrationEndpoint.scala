package dev.oauth2.server

import cats.Monad

import dev.oauth2.core.OAuth2Error
import dev.oauth2.http.ClientRegistrationResponse
import dev.oauth2.http.RegisterLogic
import dev.oauth2.http.Registration
import dev.oauth2.http.RegistrationManagementLogic
import io.circe.Json

final class RegistrationEndpoint[F[_]: Monad](
    service: RegistrationService[F]
) extends RegisterLogic[F]
    with RegistrationManagementLogic[F] {

  def apply(body: Map[String, Json]): F[Either[OAuth2Error, ClientRegistrationResponse]] =
    Registration.parse(body) match {
      case Left(error)         => Monad[F].pure(Left(error))
      case Right(registration) => service.register(registration)
    }

  def read(clientId: String, token: Option[String]): F[Either[OAuth2Error, ClientRegistrationResponse]] =
    service.read(clientId, token)

  def update(
      clientId: String,
      token: Option[String],
      body: Map[String, Json]
  ): F[Either[OAuth2Error, ClientRegistrationResponse]] =
    Registration.parse(body) match {
      case Left(error)         => Monad[F].pure(Left(error))
      case Right(registration) => service.update(clientId, token, registration)
    }

  def remove(clientId: String, token: Option[String]): F[Either[OAuth2Error, Unit]] =
    service.remove(clientId, token)
}
