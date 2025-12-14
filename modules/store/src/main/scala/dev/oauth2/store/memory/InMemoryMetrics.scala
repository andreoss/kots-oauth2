package dev.oauth2.store.memory

import cats.effect.kernel.Ref
import cats.syntax.functor._

import dev.oauth2.store.Metrics
import dev.oauth2.store.Observation

final class InMemoryMetrics[F[_]] private (
    state: Ref[F, Map[(String, Int), (Long, Long)]]
) extends Metrics[F] {

  def observed(observation: Observation): F[Unit] =
    state.update { counters =>
      val key = (observation.path, observation.status)
      val (count, nanos) = counters.getOrElse(key, (0L, 0L))
      counters.updated(key, (count + 1L, nanos + observation.nanos))
    }

  def counters: F[Map[(String, Int), (Long, Long)]] = state.get
}

object InMemoryMetrics {

  def create[F[_]: cats.effect.Sync]: F[InMemoryMetrics[F]] =
    Ref.of[F, Map[(String, Int), (Long, Long)]](Map.empty).map(state => new InMemoryMetrics(state))
}
