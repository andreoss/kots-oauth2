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

  val PublicParameters: Map[Kty, Set[String]] = Map(
    Kty.Rsa -> Set("n", "e"),
    Kty.Ec -> Set("crv", "x", "y"),
    Kty.Okp -> Set("crv", "x")
  )

  def render(document: Jwks): Json =
    Json.obj(FieldKeys -> Json.arr(document.keys.map(renderKey): _*))

  private def renderKey(key: Jwk): Json = {
    val public = PublicParameters.getOrElse(key.kty, Set.empty)
    Json.fromFields(
      key.parameters.toList.collect {
        case (name, value) if public.contains(name) => name -> Json.fromString(value)
      } ++ List(
        FieldKid -> Json.fromString(key.kid.value),
        FieldKty -> Json.fromString(key.kty.value),
        FieldAlg -> Json.fromString(key.alg.value),
        FieldUse -> Json.fromString(key.use.value)
      )
    )
  }
}
