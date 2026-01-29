package kots.oauth2.server

import cats.syntax.all._
import cats.Monad

import kots.oauth2.core.OAuth2Error
import kots.oauth2.http.DeviceAuthorizationLogic
import kots.oauth2.http.IntrospectionLogic
import kots.oauth2.http.TokenLogic
import kots.oauth2.http.VerificationLogic
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

  val VerificationKey: String = "verification"

  def verification[F[_]: Monad](
      limiter: RateLimiter[F],
      inner: VerificationLogic[F]
  ): VerificationLogic[F] =
    new VerificationLogic[F] {
      def page(session: Option[String]) = inner.page(session)

      def decide(session: Option[String], parameters: Map[String, String]) =
        limiter.acquire(VerificationKey).flatMap {
          case Some(retryAfter) =>
            (OAuth2Error.RateLimited(retryAfter): OAuth2Error).asLeft[String].pure[F]
          case None => inner.decide(session, parameters)
        }
    }

  private def limited[F[_]: Monad, A](limiter: RateLimiter[F], parameters: Map[String, String])(
      inner: => F[Either[OAuth2Error, A]]
  ): F[Either[OAuth2Error, A]] =
    limiter.acquire(key(parameters)).flatMap {
      case Some(retryAfter) =>
        (OAuth2Error.RateLimited(retryAfter): OAuth2Error).asLeft[A].pure[F]
      case None => inner
    }
}
