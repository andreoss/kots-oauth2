package kots.oauth2.server

import cats.Monad
import cats.syntax.flatMap._

import kots.oauth2.core.ClientAuthInput
import kots.oauth2.core.OAuth2Error
import kots.oauth2.http.ParLogic
import kots.oauth2.http.PushedAuthorizationResponse

final class PushedAuthorizationEndpoint[F[_]: Monad](
    authentication: ClientAuthentication[F],
    service: PushedAuthorizationService[F]
) extends ParLogic[F] {

  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, PushedAuthorizationResponse]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(input)   =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => Monad[F].pure(Left(error))
          case Right(client) => service.push(parameters, client)
        }
    }
}
