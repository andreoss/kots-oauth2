package dev.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.functor._

import dev.oauth2.core.ClientId
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.store.ConsentRecord
import dev.oauth2.store.ConsentStore

final class InMemoryConsentStore[F[_]: Monad] private (
    state: Ref[F, Map[(ClientId, Subject), Scopes]]
) extends ConsentStore[F] {

  def grant(record: ConsentRecord): F[Unit] =
    state.update { consents =>
      val key = (record.clientId, record.subject)
      consents.updated(key, Scopes.union(consents.getOrElse(key, Scopes.empty), record.scopes))
    }

  def revoke(clientId: ClientId, subject: Subject): F[Unit] =
    state.update(_ - ((clientId, subject)))

  def decide(clientId: ClientId, subject: Subject, scopes: Scopes): F[Boolean] =
    state.get.map(consents =>
      consents.get((clientId, subject)).exists(allowed => Scopes.isSubsetOf(scopes, allowed))
    )
}

object InMemoryConsentStore {

  def create[F[_]: cats.effect.Sync]: F[InMemoryConsentStore[F]] =
    Ref.of[F, Map[(ClientId, Subject), Scopes]](Map.empty).map(state => new InMemoryConsentStore(state))
}
