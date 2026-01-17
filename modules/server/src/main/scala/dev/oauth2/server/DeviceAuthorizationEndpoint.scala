package dev.oauth2.server

import cats.Monad
import cats.syntax.flatMap._

import dev.oauth2.core.ClientAuthInput
import dev.oauth2.core.DeviceAuthorizationRequest
import dev.oauth2.core.OAuth2Error
import dev.oauth2.http.DeviceAuthorizationLogic
import dev.oauth2.http.DeviceAuthorizationResponse

final class DeviceAuthorizationEndpoint[F[_]: Monad](
    authentication: ClientAuthentication[F],
    service: DeviceAuthorizationService[F]
) extends DeviceAuthorizationLogic[F] {

  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, DeviceAuthorizationResponse]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(input)   =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => Monad[F].pure(Left(error))
          case Right(client) =>
            DeviceAuthorizationRequest.from(parameters).toEither match {
              case Left(failures) => Monad[F].pure(Left(failures.head))
              case Right(request) => service.authorize(request, client)
            }
        }
    }
}
