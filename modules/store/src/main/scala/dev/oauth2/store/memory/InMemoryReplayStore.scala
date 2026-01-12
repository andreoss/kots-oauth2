package dev.oauth2.store.memory

import java.time.Instant

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.Clock
import dev.oauth2.core.JwtId
import dev.oauth2.store.ReplayStore

final class InMemoryReplayStore[F[_]: Monad] private (
    state: Ref[F, Map[JwtId, Instant]],
    clock: Clock[F]
) extends ReplayStore[F] {

  def record(id: JwtId, expiresAt: Instant): F[Boolean] =
    clock.instant.flatMap { now =>
      state.modify { seen =>
        val live = seen.filter { case (_, expiry) => expiry.isAfter(now) }
        if (live.contains(id)) (live, false)
        else (live.updated(id, expiresAt), true)
      }
    }
}

object InMemoryReplayStore {

  def create[F[_]: cats.effect.Sync](clock: Clock[F]): F[InMemoryReplayStore[F]] =
    Ref.of[F, Map[JwtId, Instant]](Map.empty).map(state => new InMemoryReplayStore(state, clock))
}
