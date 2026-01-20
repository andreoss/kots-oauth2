package kots.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.store.CodeRecord
import kots.oauth2.store.CodeStore

final class InMemoryCodeStore[F[_]: Monad] private (
    state: Ref[F, Map[AuthorizationCode, CodeRecord]],
    issued: Ref[F, Map[AuthorizationCode, GrantId]],
    clock: Clock[F]
) extends CodeStore[F] {

  def save(record: CodeRecord): F[Unit] =
    state.update(_.updated(record.code, record))

  def consume(code: AuthorizationCode): F[Option[CodeRecord]] =
    clock.instant.flatMap { now =>
      state.modify { codes =>
        codes.get(code) match {
          case Some(record) if !record.isExpired(now) => (codes - code, Some(record))
          case Some(_)                                => (codes - code, None)
          case None                                   => (codes, None)
        }
      }
    }

  def redeem(code: AuthorizationCode, grant: GrantId): F[Unit] =
    issued.update(_.updated(code, grant))

  def redeemed(code: AuthorizationCode): F[Option[GrantId]] =
    issued.get.map(_.get(code))

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      state.modify { codes =>
        val (dead, live) = codes.partition { case (_, record) => record.isExpired(now) }
        (live, dead.size)
      }
    }
}

object InMemoryCodeStore {

  def create[F[_]: cats.effect.Sync](clock: Clock[F]): F[InMemoryCodeStore[F]] =
    for {
      state <- Ref.of[F, Map[AuthorizationCode, CodeRecord]](Map.empty)
      issued <- Ref.of[F, Map[AuthorizationCode, GrantId]](Map.empty)
    } yield new InMemoryCodeStore(state, issued, clock)
}
