package kots.oauth2.server

import cats.syntax.all._
import cats.Monad

import kots.oauth2.core.ClientAuthInput
import kots.oauth2.core.DeviceAuthorizationRequest
import kots.oauth2.core.OAuth2Error
import kots.oauth2.http.DeviceAuthorizationLogic
import kots.oauth2.http.DeviceAuthorizationResponse

final class DeviceAuthorizationEndpoint[F[_]: Monad](
    authentication: ClientAuthentication[F],
    service: DeviceAuthorizationService[F]
) extends DeviceAuthorizationLogic[F] {

  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, DeviceAuthorizationResponse]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => failures.head.asLeft.pure[F]
      case Right(input)   =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => error.asLeft.pure[F]
          case Right(client) =>
            DeviceAuthorizationRequest.from(parameters).toEither match {
              case Left(failures) => failures.head.asLeft.pure[F]
              case Right(request) => service.authorize(request, client)
            }
        }
    }
}
