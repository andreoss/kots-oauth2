package dev.oauth2.server

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.AuthorizationRequest
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.State
import dev.oauth2.http.AuthorizationRedirect
import dev.oauth2.http.AuthorizeLogic
import dev.oauth2.http.Form
import dev.oauth2.store.ClientStore

final class AuthorizationEndpoint[F[_]: Monad](
    clients: ClientStore[F],
    login: Login[F],
    service: AuthorizationService[F]
) extends AuthorizeLogic[F] {

  def apply(parameters: Map[String, String]): F[Either[OAuth2Error, AuthorizationRedirect]] =
    AuthorizationRequest.from(parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(request) =>
        clients.find(request.clientId).flatMap {
          case None =>
            Monad[F].pure(Left(OAuth2Error.InvalidRequest(Some("client is not registered")): OAuth2Error))
          case Some(client) =>
            service.target(client, request.redirectUri) match {
              case Left(error) => Monad[F].pure(Left(error))
              case Right(target) =>
                login.subject.flatMap {
                  case None =>
                    Monad[F].pure(
                      Right(AuthorizationEndpoint.refused(target, OAuth2Error.AccessDenied(), request.state))
                    )
                  case Some(subject) =>
                    service.issue(request, client, subject, AuthorizationDetails.empty).map {
                      case Right(code) => Right(AuthorizationEndpoint.granted(target, code, request.state))
                      case Left(error) => Right(AuthorizationEndpoint.refused(target, error, request.state))
                    }
                }
            }
        }
    }
}

object AuthorizationEndpoint {

  def granted(target: RedirectUri, code: AuthorizationCode, state: Option[State]): AuthorizationRedirect =
    redirect(target, Map("code" -> code.value) ++ state.map(value => "state" -> value.value))

  def refused(target: RedirectUri, error: OAuth2Error, state: Option[State]): AuthorizationRedirect =
    redirect(target, error.body ++ state.map(value => "state" -> value.value))

  private def redirect(target: RedirectUri, params: Map[String, String]): AuthorizationRedirect = {
    val separator = if (target.value.contains("?")) "&" else "?"
    AuthorizationRedirect(target.value + separator + Form.render(params))
  }
}
