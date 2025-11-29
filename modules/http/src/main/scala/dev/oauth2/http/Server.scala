package dev.oauth2.http

import cats.Applicative
import cats.Functor
import cats.syntax.functor._

import dev.oauth2.core.AuthorizationServerMetadata
import dev.oauth2.core.IntrospectionResponse
import dev.oauth2.core.OAuth2Error
import dev.oauth2.jose.Jwks
import io.circe.Json
import sttp.tapir.server.ServerEndpoint

trait TokenLogic[F[_]] {
  def apply(
      basic: Option[String],
      parameters: Map[String, String]
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

object Server {

  def token[F[_]: Functor](logic: TokenLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any, F](
      Endpoints.token,
      _ => input => logic(input._1, input._2).map(_.map(TokenResponse.render))
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

  def metadata[F[_]: Applicative](document: AuthorizationServerMetadata): ServerEndpoint[Any, F] =
    ServerEndpoint.public[Unit, OAuth2Error, Map[String, Json], Any, F](
      Endpoints.metadata,
      _ => _ => Applicative[F].pure(Right(Metadata.render(document)))
    )

  def jwks[F[_]: Functor](document: F[Jwks]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[Unit, OAuth2Error, Map[String, Json], Any, F](
      Endpoints.jwks,
      _ => _ => document.map(keys => Right(JwkSet.render(keys)): Either[OAuth2Error, Map[String, Json]])
    )
}
