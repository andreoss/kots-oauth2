package dev.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.AccessToken
import dev.oauth2.core.AccessTokenHash
import dev.oauth2.core.Clock
import dev.oauth2.core.GrantId
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.RefreshTokenHash
import dev.oauth2.store.TokenRecord
import dev.oauth2.store.TokenStore

final class InMemoryTokenStore[F[_]: Monad] private (
    state: Ref[F, Map[AccessTokenHash, TokenRecord]],
    retired: Ref[F, Map[RefreshTokenHash, GrantId]],
    clock: Clock[F]
) extends TokenStore[F] {

  def save(record: TokenRecord): F[Unit] =
    state.update(_.updated(record.accessTokenHash, record))

  def findByAccess(token: AccessToken): F[Option[TokenRecord]] =
    clock.instant.flatMap { now =>
      state.modify { tokens =>
        tokens.get(AccessTokenHash.of(token)) match {
          case Some(record) if !record.isAccessExpired(now) && record.matchesAccess(token) =>
            (tokens, Some(record))
          case Some(record) => (tokens - record.accessTokenHash, None)
          case None         => (tokens, None)
        }
      }
    }

  def findByRefresh(token: RefreshToken): F[Option[TokenRecord]] =
    clock.instant.flatMap { now =>
      state.modify { tokens =>
        tokens.values.find(_.matchesRefresh(token)) match {
          case Some(record) if !record.isRefreshExpired(now) => (tokens, Some(record))
          case Some(record)                                  => (tokens - record.accessTokenHash, None)
          case None                                          => (tokens, None)
        }
      }
    }

  def drop(refreshToken: RefreshToken): F[Unit] =
    state.update(_.filterNot { case (_, record) => record.matchesRefresh(refreshToken) })

  def revokeGrant(grantId: GrantId): F[Unit] =
    state.update(_.filterNot { case (_, record) => record.grantId == grantId })

  def retire(refreshToken: RefreshToken, grantId: GrantId): F[Unit] =
    drop(refreshToken) >> retired.update(_.updated(RefreshTokenHash.of(refreshToken), grantId))

  def rotated(refreshToken: RefreshToken): F[Option[GrantId]] =
    retired.get.map(_.get(RefreshTokenHash.of(refreshToken)))
}

object InMemoryTokenStore {

  def create[F[_]: cats.effect.Sync](clock: Clock[F]): F[InMemoryTokenStore[F]] =
    for {
      state <- Ref.of[F, Map[AccessTokenHash, TokenRecord]](Map.empty)
      retired <- Ref.of[F, Map[RefreshTokenHash, GrantId]](Map.empty)
    } yield new InMemoryTokenStore(state, retired, clock)
}
