package dev.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.functor._

import dev.oauth2.core.KeyId
import dev.oauth2.jose.Jwk
import dev.oauth2.jose.Jwks
import dev.oauth2.store.KeyRecord
import dev.oauth2.store.KeyStore

final class InMemoryKeyStore[F[_]: Monad] private (
    state: Ref[F, Vector[KeyRecord]]
) extends KeyStore[F] {

  def jwks: F[Jwks] =
    state.get.map(records => Jwks(records.map(_.key).toList))

  def current: F[Option[Jwk]] =
    state.get.map(_.reverse.collectFirst { case record if !record.retired => record.key })

  def find(kid: KeyId): F[Option[Jwk]] =
    state.get.map(_.find(_.key.kid == kid).map(_.key))

  def add(key: Jwk): F[Unit] =
    state.update(records => records.filterNot(_.key.kid == key.kid) :+ KeyRecord(key, retired = false))

  def retire(kid: KeyId): F[Unit] =
    state.update(_.map(record => if (record.key.kid == kid) record.copy(retired = true) else record))
}

object InMemoryKeyStore {

  def create[F[_]: cats.effect.Sync]: F[InMemoryKeyStore[F]] =
    Ref.of[F, Vector[KeyRecord]](Vector.empty).map(new InMemoryKeyStore(_))
}
