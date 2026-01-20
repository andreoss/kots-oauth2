package kots.oauth2.host

import scala.concurrent.duration.FiniteDuration

import cats.effect.Temporal
import cats.syntax.foldable._
import fs2.Stream

object Sweeper {

  def stream[F[_]: Temporal](interval: FiniteDuration, sweeps: List[F[Int]]): Stream[F, Int] =
    Stream
      .awakeEvery[F](interval)
      .evalMap(_ => sweeps.foldMapM(identity))
}
