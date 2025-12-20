package kots.oauth2.store

import cats.Applicative

final case class Observation(path: String, status: Int, nanos: Long)

trait Metrics[F[_]] {

  def observed(observation: Observation): F[Unit]
}

object Metrics {

  def noop[F[_]: Applicative]: Metrics[F] =
    new Metrics[F] {
      def observed(observation: Observation): F[Unit] = Applicative[F].unit
    }
}
