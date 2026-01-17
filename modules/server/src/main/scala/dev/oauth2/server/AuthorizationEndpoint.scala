package dev.oauth2.server

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.AuthorizationRequest
import dev.oauth2.core.Issuer
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.RequestUri
import dev.oauth2.core.State
import dev.oauth2.http.AuthorizationRedirect
import dev.oauth2.http.AuthorizeLogic
import dev.oauth2.http.Form
import dev.oauth2.store.ClientStore
import dev.oauth2.store.PushedRequestStore

final class AuthorizationEndpoint[F[_]: Monad](
    clients: ClientStore[F],
    login: Login[F],
    service: AuthorizationService[F],
    issuer: Issuer,
    pushed: Option[PushedRequestStore[F]] = None
) extends AuthorizeLogic[F] {

  def apply(parameters: Map[String, String]): F[Either[OAuth2Error, AuthorizationRedirect]] =
    parameters.get("request_uri") match {
      case None      => handle(parameters)
      case Some(raw) => resolve(raw, parameters)
    }

  private def resolve(
      raw: String,
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, AuthorizationRedirect]] =
    if ((parameters.keySet -- AuthorizationEndpoint.PushedParameters).nonEmpty)
      Monad[F].pure(Left(OAuth2Error.InvalidRequest(Some("request_uri stands alone")): OAuth2Error))
    else
      (
        RequestUri
          .from(raw)
          .left
          .map(_ => OAuth2Error.InvalidRequest(Some("not a request_uri")): OAuth2Error),
        pushed
      ) match {
        case (Left(error), _) => Monad[F].pure(Left(error))
        case (_, None)        =>
          Monad[F].pure(Left(OAuth2Error.InvalidRequest(Some("request_uri is not supported")): OAuth2Error))
        case (Right(uri), Some(store)) =>
          store.consume(uri).flatMap {
            case Some(record) if parameters.get("client_id").contains(record.clientId.value) =>
              handle(record.parameters)
            case _ =>
              Monad[F].pure(Left(OAuth2Error.InvalidRequest(Some("unknown request_uri")): OAuth2Error))
          }
      }

  private def handle(parameters: Map[String, String]): F[Either[OAuth2Error, AuthorizationRedirect]] =
    AuthorizationRequest.from(parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(request) =>
        clients.find(request.clientId).flatMap {
          case None =>
            Monad[F].pure(Left(OAuth2Error.InvalidRequest(Some("client is not registered")): OAuth2Error))
          case Some(client) =>
            service.target(client, request.redirectUri) match {
              case Left(error)   => Monad[F].pure(Left(error))
              case Right(target) =>
                login.subject.flatMap {
                  case None =>
                    Monad[F].pure(
                      Right(
                        AuthorizationEndpoint
                          .refused(target, OAuth2Error.AccessDenied(), request.state, issuer)
                      )
                    )
                  case Some(subject) =>
                    service.issue(request, client, subject, AuthorizationDetails.empty).map {
                      case Right(code) =>
                        Right(AuthorizationEndpoint.granted(target, code, request.state, issuer))
                      case Left(error) =>
                        Right(AuthorizationEndpoint.refused(target, error, request.state, issuer))
                    }
                }
            }
        }
    }
}

object AuthorizationEndpoint {

  val IssParameter: String = "iss"

  val PushedParameters: Set[String] = Set("client_id", "request_uri")

  def granted(
      target: RedirectUri,
      code: AuthorizationCode,
      state: State,
      issuer: Issuer
  ): AuthorizationRedirect =
    redirect(
      target,
      Map("code" -> code.value, IssParameter -> issuer.value, "state" -> state.value)
    )

  def refused(
      target: RedirectUri,
      error: OAuth2Error,
      state: State,
      issuer: Issuer
  ): AuthorizationRedirect =
    redirect(
      target,
      error.body ++ Map(IssParameter -> issuer.value, "state" -> state.value)
    )

  private def redirect(target: RedirectUri, params: Map[String, String]): AuthorizationRedirect = {
    val separator = if (target.value.contains("?")) "&" else "?"
    AuthorizationRedirect(target.value + separator + Form.render(params))
  }
}
