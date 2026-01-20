package kots.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.Clock
import kots.oauth2.core.RequestUri
import kots.oauth2.store.PushedRequest
import kots.oauth2.store.PushedRequestStore

final class InMemoryPushedRequestStore[F[_]: Monad] private (
    state: Ref[F, Map[RequestUri, PushedRequest]],
    clock: Clock[F]
) extends PushedRequestStore[F] {

  def save(record: PushedRequest): F[Unit] =
    state.update(_.updated(record.uri, record))

  def consume(uri: RequestUri): F[Option[PushedRequest]] =
    clock.instant.flatMap { now =>
      state.modify { pushed =>
        pushed.get(uri) match {
          case Some(record) if !record.isExpired(now) => (pushed - uri, Some(record))
          case Some(_)                                => (pushed - uri, None)
          case None                                   => (pushed, None)
        }
      }
    }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      state.modify { pushed =>
        val (dead, live) = pushed.partition { case (_, record) => record.isExpired(now) }
        (live, dead.size)
      }
    }
}

object InMemoryPushedRequestStore {

  def create[F[_]: cats.effect.Sync](clock: Clock[F]): F[InMemoryPushedRequestStore[F]] =
    Ref
      .of[F, Map[RequestUri, PushedRequest]](Map.empty)
      .map(state => new InMemoryPushedRequestStore(state, clock))
}
