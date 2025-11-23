package dev.oauth2.jose

import dev.oauth2.core.KeyId
import io.circe.Json

final case class Jwks(keys: List[Jwk]) {

  def find(kid: KeyId): Option[Jwk] = keys.find(_.kid == kid)
}

object Jwks {

  val empty: Jwks = Jwks(Nil)

  val FieldKeys: String = "keys"

  val FieldKid: String = "kid"

  val FieldKty: String = "kty"

  val FieldAlg: String = "alg"

  val FieldUse: String = "use"

  def render(document: Jwks): Json =
    Json.obj(FieldKeys -> Json.arr(document.keys.map(renderKey): _*))

  private def renderKey(key: Jwk): Json =
    Json.fromFields(
      List(
        FieldKid -> Json.fromString(key.kid.value),
        FieldKty -> Json.fromString(key.kty.value),
        FieldAlg -> Json.fromString(key.alg.value),
        FieldUse -> Json.fromString(Jwk.Use)
      ) ++ key.parameters.toList.map { case (name, value) => name -> Json.fromString(value) }
    )
}
