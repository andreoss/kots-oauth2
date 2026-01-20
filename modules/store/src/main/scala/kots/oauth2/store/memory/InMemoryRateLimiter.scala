package kots.oauth2.store.memory

import java.time.Instant

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.Clock
import kots.oauth2.store.RateLimiter

final class InMemoryRateLimiter[F[_]: Monad] private (
    state: Ref[F, Map[String, InMemoryRateLimiter.Window]],
    clock: Clock[F],
    limit: Int,
    windowSeconds: Long
) extends RateLimiter[F] {

  def acquire(key: String): F[Option[Long]] =
    clock.instant.flatMap { now =>
      state.modify { windows =>
        windows.get(key).filter(window => now.isBefore(window.resetAt)) match {
          case None =>
            val opened = InMemoryRateLimiter.Window(now.plusSeconds(windowSeconds), 1)
            (windows.updated(key, opened), None)
          case Some(window) if window.count < limit =>
            (windows.updated(key, window.copy(count = window.count + 1)), None)
          case Some(window) =>
            val remaining = window.resetAt.getEpochSecond - now.getEpochSecond
            (windows, Some(math.max(1L, remaining)))
        }
      }
    }
}

object InMemoryRateLimiter {

  private[memory] final case class Window(resetAt: Instant, count: Int)

  def create[F[_]: cats.effect.Sync](
      clock: Clock[F],
      limit: Int,
      windowSeconds: Long
  ): F[InMemoryRateLimiter[F]] =
    Ref
      .of[F, Map[String, Window]](Map.empty)
      .map(state => new InMemoryRateLimiter(state, clock, limit, windowSeconds))
}
