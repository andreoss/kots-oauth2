package kots.oauth2.server

import cats.syntax.all._
import cats.Monad

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
      case Left(failures) => failures.head.asLeft.pure[F]
      case Right(input)   =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => error.asLeft.pure[F]
          case Right(client) =>
            ClientIdentity.named(parameters, client) match {
              case Left(error)     => error.asLeft[PushedAuthorizationResponse].pure[F]
              case Right(enriched) => service.push(enriched, client)
            }
        }
    }
}
