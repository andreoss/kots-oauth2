package kots.oauth2.server

import cats.Applicative

import kots.oauth2.core.Issuer
import kots.oauth2.jose.Jwks

trait AssertionIssuers[F[_]] {

  def keys(issuer: Issuer): F[Option[Jwks]]
}

object AssertionIssuers {

  def static[F[_]: Applicative](trusted: Map[Issuer, Jwks]): AssertionIssuers[F] =
    new AssertionIssuers[F] {
      def keys(issuer: Issuer): F[Option[Jwks]] = Applicative[F].pure(trusted.get(issuer))
    }
}
