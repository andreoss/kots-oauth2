package dev.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.functor._

import dev.oauth2.core.ClientId
import dev.oauth2.store.Client
import dev.oauth2.store.ClientStore

final class InMemoryClientStore[F[_]: Monad] private (
    state: Ref[F, Map[ClientId, Client]]
) extends ClientStore[F] {

  def find(id: ClientId): F[Option[Client]] =
    state.get.map(_.get(id))
}

object InMemoryClientStore {

  def create[F[_]: cats.effect.Sync](clients: List[Client]): F[InMemoryClientStore[F]] =
    Ref.of[F, Map[ClientId, Client]](clients.map(client => client.id -> client).toMap).map { state =>
      new InMemoryClientStore(state)
    }
}
