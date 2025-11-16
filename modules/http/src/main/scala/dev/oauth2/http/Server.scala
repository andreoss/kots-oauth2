package dev.oauth2.http

import cats.Functor
import cats.syntax.functor._

import dev.oauth2.core.OAuth2Error
import sttp.tapir.server.ServerEndpoint

trait TokenLogic[F[_]] {
  def apply(
      authorization: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, TokenResponse]]
}

object Server {

  def token[F[_]: Functor](logic: TokenLogic[F]): ServerEndpoint[Any, F] =
    ServerEndpoint.public[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any, F](
      Endpoints.token,
      _ => input => logic(input._1, input._2).map(_.map(TokenResponse.render))
    )
}
