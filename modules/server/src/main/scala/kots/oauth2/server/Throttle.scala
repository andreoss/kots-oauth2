package kots.oauth2.server

import cats.Monad
import cats.syntax.flatMap._

import kots.oauth2.core.OAuth2Error
import kots.oauth2.http.DeviceAuthorizationLogic
import kots.oauth2.http.IntrospectionLogic
import kots.oauth2.http.TokenLogic
import kots.oauth2.store.RateLimiter

object Throttle {

  val AnonymousKey: String = "anonymous"

  def key(parameters: Map[String, String]): String =
    parameters.getOrElse("client_id", AnonymousKey)

  def token[F[_]: Monad](limiter: RateLimiter[F], inner: TokenLogic[F]): TokenLogic[F] =
    new TokenLogic[F] {
      def apply(
          basic: Option[String],
          parameters: Map[String, String],
          proof: Option[String],
          certificate: Option[String]
      ) =
        limited(limiter, parameters)(inner(basic, parameters, proof, certificate))
    }

  def introspection[F[_]: Monad](
      limiter: RateLimiter[F],
      inner: IntrospectionLogic[F]
  ): IntrospectionLogic[F] =
    new IntrospectionLogic[F] {
      def apply(basic: Option[String], parameters: Map[String, String]) =
        limited(limiter, parameters)(inner(basic, parameters))
    }

  def device[F[_]: Monad](
      limiter: RateLimiter[F],
      inner: DeviceAuthorizationLogic[F]
  ): DeviceAuthorizationLogic[F] =
    new DeviceAuthorizationLogic[F] {
      def apply(basic: Option[String], parameters: Map[String, String]) =
        limited(limiter, parameters)(inner(basic, parameters))
    }

  private def limited[F[_]: Monad, A](limiter: RateLimiter[F], parameters: Map[String, String])(
      inner: => F[Either[OAuth2Error, A]]
  ): F[Either[OAuth2Error, A]] =
    limiter.acquire(key(parameters)).flatMap {
      case Some(retryAfter) =>
        Monad[F].pure(Left(OAuth2Error.RateLimited(retryAfter)): Either[OAuth2Error, A])
      case None => inner
    }
}
