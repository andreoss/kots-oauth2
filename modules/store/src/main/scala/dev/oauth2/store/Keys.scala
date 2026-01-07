package dev.oauth2.store

import dev.oauth2.core.KeyId
import dev.oauth2.jose.Jwk
import dev.oauth2.jose.Jwks

final case class KeyRecord(key: Jwk, retired: Boolean)

trait KeyStore[F[_]] {
  def jwks: F[Jwks]

  def current: F[Option[Jwk]]

  def find(kid: KeyId): F[Option[Jwk]]

  def add(key: Jwk): F[Unit]

  def retire(kid: KeyId): F[Unit]
}
