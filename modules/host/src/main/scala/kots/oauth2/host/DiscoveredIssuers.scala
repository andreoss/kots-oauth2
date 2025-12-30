package kots.oauth2.host

import cats.effect.Concurrent
import cats.syntax.all._

import kots.oauth2.client.Discovery
import kots.oauth2.core.Clock
import kots.oauth2.core.Issuer
import kots.oauth2.core.Lifetime
import kots.oauth2.jose.Jwks
import kots.oauth2.server.AssertionIssuers
import org.http4s.client.Client

final class DiscoveredIssuers[F[_]: Concurrent] private (trusted: Map[Issuer, Discovery[F]])
    extends AssertionIssuers[F] {

  def keys(issuer: Issuer): F[Option[Jwks]] =
    trusted.get(issuer) match {
      case None            => none[Jwks].pure[F]
      case Some(discovery) => discovery.keys.map(_.toOption)
    }
}

object DiscoveredIssuers {

  val DefaultTtl: Lifetime =
    Lifetime.fromSeconds(3600L).fold(failure => sys.error(failure.toString), identity)

  def create[F[_]: Concurrent](
      transport: Client[F],
      clock: Clock[F],
      trusted: List[Issuer],
      ttl: Lifetime = DefaultTtl
  ): F[DiscoveredIssuers[F]] =
    trusted
      .traverse(issuer => Discovery.create[F](transport, issuer, clock, ttl).map(issuer -> _))
      .map(pairs => new DiscoveredIssuers(pairs.toMap))
}
