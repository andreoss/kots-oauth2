package dev.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.functor._

import dev.oauth2.core.GrantId
import dev.oauth2.store.Grant
import dev.oauth2.store.GrantStore

final class InMemoryGrantStore[F[_]: Monad] private (
    state: Ref[F, Map[GrantId, Grant]]
) extends GrantStore[F] {

  def save(grant: Grant): F[Unit] =
    state.update(_.updated(grant.id, grant))

  def find(id: GrantId): F[Option[Grant]] =
    state.get.map(_.get(id))

  def revoke(id: GrantId): F[Unit] =
    state.update { grants =>
      grants.get(id).fold(grants)(grant => grants.updated(id, grant.copy(revoked = true)))
    }
}

object InMemoryGrantStore {

  def create[F[_]: cats.effect.Sync]: F[InMemoryGrantStore[F]] =
    Ref.of[F, Map[GrantId, Grant]](Map.empty).map(new InMemoryGrantStore(_))
}
