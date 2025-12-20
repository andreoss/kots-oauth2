package kots.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.functor._

import kots.oauth2.core.ClientId
import kots.oauth2.store.Client
import kots.oauth2.store.ClientStore

final class InMemoryClientStore[F[_]: Monad] private (
    state: Ref[F, Map[ClientId, Client]]
) extends ClientStore[F] {

  def find(id: ClientId): F[Option[Client]] =
    state.get.map(_.get(id))

  def save(client: Client): F[Unit] =
    state.update(_.updated(client.id, client))

  def delete(id: ClientId): F[Unit] =
    state.update(_ - id)
}

object InMemoryClientStore {

  def create[F[_]: cats.effect.Sync](clients: List[Client]): F[InMemoryClientStore[F]] =
    Ref.of[F, Map[ClientId, Client]](clients.map(client => client.id -> client).toMap).map { state =>
      new InMemoryClientStore(state)
    }
}
