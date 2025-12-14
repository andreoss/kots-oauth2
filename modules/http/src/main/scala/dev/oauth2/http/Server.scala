package dev.oauth2.http

import cats.Applicative
import cats.Functor
import cats.syntax.functor._

import dev.oauth2.core.AuthorizationServerMetadata
import dev.oauth2.core.IntrospectionResponse
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.ProtectedResourceMetadata
import dev.oauth2.jose.Jwks
import io.circe.Json
import sttp.tapir.server.ServerEndpoint

trait AuthorizeLogic[F[_]] {
  def apply(parameters: Map[String, String]): F[Either[OAuth2Error, AuthorizationRedirect]]
}

trait TokenLogic[F[_]] {
  def apply(
      basic: Option[String],
      parameters: Map[String, String],
      proof: Option[String] = None
  ): F[Either[OAuth2Error, TokenResponse]]
}

trait RevocationLogic[F[_]] {
  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, Unit]]
}

trait IntrospectionLogic[F[_]] {
  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, IntrospectionResponse]]
}

trait DeviceAuthorizationLogic[F[_]] {
  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, DeviceAuthorizationResponse]]
}

trait ParLogic[F[_]] {
  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, PushedAuthorizationResponse]]
}

trait RegisterLogic[F[_]] {
  def apply(body: Map[String, Json]): F[Either[OAuth2Error, ClientRegistrationResponse]]
}

trait RegistrationManagementLogic[F[_]] {
  def read(clientId: String, token: Option[String]): F[Either[OAuth2Error, ClientRegistrationResponse]]

  def update(
      clientId: String,
      token: Option[String],
      body: Map[String, Json]
  ): F[Either[OAuth2Error, ClientRegistrationResponse]]

  def remove(clientId: String, token: Option[String]): F[Either[OAuth2Error, Unit]]
}

trait ReadinessLogic[F[_]] {
  def report: F[HealthReport]
}

object Server {

  def authorize[F[_]: Functor](logic: AuthorizeLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[Map[String, String], OAuth2Error, String, Any, F](
      Endpoints.authorize,
      _ => parameters => logic(parameters).map(_.map(_.location))
    )

  def par[F[_]: Functor](logic: ParLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any, F](
      Endpoints.par,
      _ => input => logic(input._1, input._2).map(_.map(PushedAuthorizationResponse.render))
    )

  def register[F[_]: Functor](logic: RegisterLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[Map[String, Json], OAuth2Error, Map[String, Json], Any, F](
      Endpoints.register,
      _ => body => logic(body).map(_.map(ClientRegistrationResponse.render))
    )

  def registrationRead[F[_]: Functor](logic: RegistrationManagementLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[(String, Option[String]), OAuth2Error, Map[String, Json], Any, F](
      Endpoints.registrationRead,
      _ => input => logic.read(input._1, input._2).map(_.map(ClientRegistrationResponse.render))
    )

  def registrationUpdate[F[_]: Functor](logic: RegistrationManagementLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint
      .public[(String, Option[String], Map[String, Json]), OAuth2Error, Map[String, Json], Any, F](
        Endpoints.registrationUpdate,
        _ => input => logic.update(input._1, input._2, input._3).map(_.map(ClientRegistrationResponse.render))
      )

  def registrationDelete[F[_]](logic: RegistrationManagementLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[(String, Option[String]), OAuth2Error, Unit, Any, F](
      Endpoints.registrationDelete,
      _ => input => logic.remove(input._1, input._2)
    )

  def token[F[_]: Functor](logic: TokenLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint
      .public[(Option[String], Map[String, String], Option[String]), OAuth2Error, Map[
        String,
        String
      ], Any, F](
        Endpoints.token,
        _ => input => logic(input._1, input._2, input._3).map(_.map(TokenResponse.render))
      )

  def revocation[F[_]](logic: RevocationLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[(Option[String], Map[String, String]), OAuth2Error, Unit, Any, F](
      Endpoints.revocation,
      _ => input => logic(input._1, input._2)
    )

  def introspection[F[_]: Functor](logic: IntrospectionLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any, F](
      Endpoints.introspection,
      _ => input => logic(input._1, input._2).map(_.map(_.body))
    )

  def deviceAuthorization[F[_]: Functor](logic: DeviceAuthorizationLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any, F](
      Endpoints.deviceAuthorization,
      _ => input => logic(input._1, input._2).map(_.map(DeviceAuthorizationResponse.render))
    )

  def metadata[F[_]: Applicative](document: AuthorizationServerMetadata): ServerEndpoint[Any, F] =
    ServerEndpoint.public[Unit, OAuth2Error, Map[String, Json], Any, F](
      Endpoints.metadata,
      _ => _ => Applicative[F].pure(Right(Metadata.render(document)))
    )

  def resourceMetadata[F[_]: Applicative](document: ProtectedResourceMetadata): ServerEndpoint[Any, F] =
    ServerEndpoint.public[Unit, OAuth2Error, Map[String, Json], Any, F](
      Endpoints.resourceMetadata,
      _ => _ => Applicative[F].pure(Right(Metadata.renderResource(document)))
    )

  def jwks[F[_]: Functor](document: F[Jwks]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[Unit, OAuth2Error, Map[String, Json], Any, F](
      Endpoints.jwks,
      _ => _ => document.map(keys => Right(JwkSet.render(keys)): Either[OAuth2Error, Map[String, Json]])
    )

  def health[F[_]: Applicative]: ServerEndpoint[Any, F] =
    ServerEndpoint.public[Unit, OAuth2Error, Map[String, Json], Any, F](
      Endpoints.health,
      _ =>
        _ =>
          Applicative[F].pure(
            Right(Map("status" -> Json.fromString(HealthReport.Ok))): Either[OAuth2Error, Map[String, Json]]
          )
    )

  def ready[F[_]: Functor](logic: ReadinessLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[Unit, OAuth2Error, (sttp.model.StatusCode, Map[String, Json]), Any, F](
      Endpoints.ready,
      _ =>
        _ =>
          logic.report.map { report =>
            val status =
              if (report.healthy) sttp.model.StatusCode.Ok else sttp.model.StatusCode.ServiceUnavailable
            Right((status, HealthReport.render(report))): Either[
              OAuth2Error,
              (sttp.model.StatusCode, Map[String, Json])
            ]
          }
    )
}
