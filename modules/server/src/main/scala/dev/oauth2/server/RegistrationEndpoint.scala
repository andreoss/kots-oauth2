package dev.oauth2.server

import cats.Monad

import dev.oauth2.core.OAuth2Error
import dev.oauth2.http.ClientRegistrationResponse
import dev.oauth2.http.RegisterLogic
import dev.oauth2.http.Registration
import io.circe.Json

final class RegistrationEndpoint[F[_]: Monad](
    service: RegistrationService[F]
) extends RegisterLogic[F] {

  def apply(body: Map[String, Json]): F[Either[OAuth2Error, ClientRegistrationResponse]] =
    Registration.parse(body) match {
      case Left(error)         => Monad[F].pure(Left(error))
      case Right(registration) => service.register(registration)
    }
}
