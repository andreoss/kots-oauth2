package kots.oauth2.client

import scala.concurrent.duration.DurationLong

import cats.effect.Temporal
import cats.syntax.flatMap._

import kots.oauth2.core.Lifetime
import kots.oauth2.core.OAuth2Error

object DevicePoller {

  val SlowDownSeconds: Long = 5L

  def next(interval: Lifetime, slowedDown: Boolean): Lifetime =
    if (slowedDown)
      Lifetime.fromSeconds(interval.seconds + SlowDownSeconds).getOrElse(interval)
    else interval

  def await[F[_]: Temporal](interval: Lifetime)(
      poll: F[Either[OAuth2Error, TokenClient.Grant]]
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    poll.flatMap {
      case Left(_: OAuth2Error.AuthorizationPending) =>
        Temporal[F].sleep(interval.seconds.seconds) >> await(interval)(poll)
      case Left(_: OAuth2Error.SlowDown) =>
        val grown = next(interval, slowedDown = true)
        Temporal[F].sleep(grown.seconds.seconds) >> await(grown)(poll)
      case answered => Temporal[F].pure(answered)
    }
}
