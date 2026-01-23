package kots.oauth2.store.sql

import kots.oauth2.core.KeyId
import kots.oauth2.core.ParseFailure
import kots.oauth2.jose.Alg
import kots.oauth2.jose.Jwk
import kots.oauth2.jose.Kty

private[sql] object KeyRows {

  def encode(key: Jwk): String = DetailRows.encodeFields(key.parameters)

  def keyOf(kid: String, alg: String, joined: String): Jwk = {
    val params = DetailRows.decodeFields(joined)
    val identifier = DetailRows.required(KeyId.from(kid))
    val algorithm = DetailRows.required(Alg.from(alg))
    def param(name: String): String =
      params.getOrElse(name, DetailRows.required(Left(ParseFailure("Jwk", s"no $name parameter"))))
    algorithm.kty match {
      case Kty.Rsa => DetailRows.required(Jwk.rsa(identifier, algorithm, param("n"), param("e")))
      case Kty.Ec  =>
        DetailRows.required(Jwk.ec(identifier, algorithm, param("crv"), param("x"), param("y")))
      case Kty.Okp => DetailRows.required(Jwk.okp(identifier, algorithm, param("crv"), param("x")))
    }
  }
}
