package kots.oauth2.server

import cats.syntax.all._
import cats.Monad

import kots.oauth2.core.OAuth2Error
import kots.oauth2.http.ClientRegistrationResponse
import kots.oauth2.http.RegisterLogic
import kots.oauth2.http.Registration
import kots.oauth2.http.RegistrationManagementLogic
import io.circe.Json

final class RegistrationEndpoint[F[_]: Monad](
    service: RegistrationService[F]
) extends RegisterLogic[F]
    with RegistrationManagementLogic[F] {

  def apply(body: Map[String, Json]): F[Either[OAuth2Error, ClientRegistrationResponse]] =
    Registration.parse(body) match {
      case Left(error)         => error.asLeft.pure[F]
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
      case Left(error)         => error.asLeft.pure[F]
      case Right(registration) => service.update(clientId, token, registration)
    }

  def remove(clientId: String, token: Option[String]): F[Either[OAuth2Error, Unit]] =
    service.remove(clientId, token)
}
