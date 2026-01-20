package kots.oauth2.client

import scala.concurrent.duration.DurationLong

import cats.effect.Temporal
import cats.effect.kernel.Deferred
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.RefreshToken

final class Refresher[F[_]: Temporal] private (
    call: RefreshToken => F[Either[OAuth2Error, TokenClient.Grant]],
    flights: Ref[F, Map[RefreshToken, Deferred[F, Either[OAuth2Error, TokenClient.Grant]]]]
) {

  def refresh(token: RefreshToken): F[Either[OAuth2Error, TokenClient.Grant]] =
    Deferred[F, Either[OAuth2Error, TokenClient.Grant]].flatMap { gate =>
      flights.modify { inFlight =>
        inFlight.get(token) match {
          case Some(existing) => (inFlight, existing.get)
          case None           => (inFlight.updated(token, gate), fly(token, gate))
        }
      }.flatten
    }

  private def fly(
      token: RefreshToken,
      gate: Deferred[F, Either[OAuth2Error, TokenClient.Grant]]
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    attempt(token, 0).flatMap { answered =>
      flights.update(_ - token) >> gate.complete(answered).as(answered)
    }

  private def attempt(token: RefreshToken, retried: Int): F[Either[OAuth2Error, TokenClient.Grant]] =
    call(token).flatMap {
      case Left(error) if Refresher.transient(error) && retried < Refresher.Retries =>
        Temporal[F].sleep((Refresher.BackoffSeconds << retried).seconds) >> attempt(token, retried + 1)
      case answered => Temporal[F].pure(answered)
    }
}

object Refresher {

  val Retries: Int = 3

  val BackoffSeconds: Long = 1L

  def transient(error: OAuth2Error): Boolean =
    error match {
      case _: OAuth2Error.ServerError            => true
      case _: OAuth2Error.TemporarilyUnavailable => true
      case _                                     => false
    }

  def create[F[_]: Temporal](
      call: RefreshToken => F[Either[OAuth2Error, TokenClient.Grant]]
  ): F[Refresher[F]] =
    Ref
      .of[F, Map[RefreshToken, Deferred[F, Either[OAuth2Error, TokenClient.Grant]]]](Map.empty)
      .map(flights => new Refresher(call, flights))
}
