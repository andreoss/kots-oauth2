package dev.oauth2.jose

import dev.oauth2.core.KeyId

final case class Jwks(keys: List[Jwk]) {

  def find(kid: KeyId): Option[Jwk] = keys.find(_.kid == kid)
}

object Jwks {

  val empty: Jwks = Jwks(Nil)
}
