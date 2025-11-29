package dev.oauth2.http

import dev.oauth2.jose.Jwk
import dev.oauth2.jose.Jwks
import dev.oauth2.jose.Kty
import io.circe.Json

object JwkSet {

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

  def render(document: Jwks): Map[String, Json] =
    Map(FieldKeys -> Json.arr(document.keys.map(renderKey): _*))

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
