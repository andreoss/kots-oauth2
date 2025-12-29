package kots.oauth2.server

import cats.syntax.all._
import cats.Monad

import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.AuthorizationRequest
import kots.oauth2.core.Issuer
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.RequestUri
import kots.oauth2.core.State
import kots.oauth2.http.AuthorizationRedirect
import kots.oauth2.http.AuthorizeLogic
import kots.oauth2.http.Form
import kots.oauth2.store.ClientStore
import kots.oauth2.store.PushedRequestStore

final class AuthorizationEndpoint[F[_]: Monad](
    clients: ClientStore[F],
    login: Login[F],
    service: AuthorizationService[F],
    issuer: Issuer,
    pushed: Option[PushedRequestStore[F]] = None
) extends AuthorizeLogic[F] {

  private def invalid(reason: String): F[Either[OAuth2Error, AuthorizationRedirect]] =
    (OAuth2Error.InvalidRequest(Some(reason)): OAuth2Error).asLeft[AuthorizationRedirect].pure[F]

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
      invalid("request_uri stands alone")
    else
      (
        RequestUri
          .from(raw)
          .left
          .map(_ => OAuth2Error.InvalidRequest(Some("not a request_uri")): OAuth2Error),
        pushed
      ) match {
        case (Left(error), _) => error.asLeft.pure[F]
        case (_, None)        =>
          invalid("request_uri is not supported")
        case (Right(uri), Some(store)) =>
          store.consume(uri).flatMap {
            case Some(record) if parameters.get("client_id").contains(record.clientId.value) =>
              handle(record.parameters)
            case _ =>
              invalid("unknown request_uri")
          }
      }

  private def handle(parameters: Map[String, String]): F[Either[OAuth2Error, AuthorizationRedirect]] =
    AuthorizationRequest.from(parameters).toEither match {
      case Left(failures) => failures.head.asLeft.pure[F]
      case Right(request) =>
        clients.find(request.clientId).flatMap {
          case None =>
            invalid("client is not registered")
          case Some(client) =>
            service.target(client, request.redirectUri) match {
              case Left(error)   => error.asLeft.pure[F]
              case Right(target) =>
                login.subject.flatMap {
                  case None =>
                    AuthorizationEndpoint
                      .refused(target, OAuth2Error.AccessDenied(), request.state, issuer)
                      .asRight
                      .pure[F]
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
