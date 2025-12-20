package kots.oauth2.store

import kots.oauth2.core.KeyId
import kots.oauth2.jose.Jwk
import kots.oauth2.jose.Jwks

final case class KeyRecord(key: Jwk, retired: Boolean)

trait KeyStore[F[_]] {
  def jwks: F[Jwks]

  def current: F[Option[Jwk]]

  def find(kid: KeyId): F[Option[Jwk]]

  def add(key: Jwk): F[Unit]

  def retire(kid: KeyId): F[Unit]
}
