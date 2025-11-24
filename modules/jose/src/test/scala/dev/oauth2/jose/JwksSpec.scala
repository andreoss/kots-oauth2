package dev.oauth2.jose

import munit.FunSuite

class JwksSpec extends FunSuite {

  private val n: String = Fakes.Modulus

  private val e: String = Fakes.Exponent

  private val rsaKey: Jwk = Fakes.rsa("key-1")

  private val ecKey: Jwk = Fakes.ec("key-2")

  private val okpKey: Jwk = Fakes.okp("key-3")

  private val fixed: Set[String] = Set(Jwks.FieldKid, Jwks.FieldKty, Jwks.FieldAlg, Jwks.FieldUse)

  private def entries(document: Jwks): List[io.circe.Json] =
    Jwks
      .render(document)
      .hcursor
      .downField(Jwks.FieldKeys)
      .values
      .getOrElse(fail(s"no ${Jwks.FieldKeys} array in the document"))
      .toList

  private def field(entry: io.circe.Json, name: String): String =
    entry.hcursor.get[String](name).getOrElse(fail(s"no $name in $entry"))

  test("a document renders one entry per key") {
    val rendered = entries(Jwks(List(rsaKey, ecKey)))
    assertEquals(rendered.length, 2)
    assertEquals(rendered.map(field(_, Jwks.FieldKid)), List("key-1", "key-2"))
    assertEquals(rendered.map(field(_, Jwks.FieldKty)), List("RSA", "EC"))
    assertEquals(rendered.map(field(_, Jwks.FieldAlg)), List("RS256", "ES256"))
    assertEquals(rendered.map(field(_, Jwks.FieldUse)), List("sig", "sig"))
  }

  test("an entry carries the public parameters of its key type") {
    val entry = entries(Jwks(List(rsaKey))).head
    assertEquals(field(entry, "n"), n)
    assertEquals(field(entry, "e"), e)
    assertEquals(entry.hcursor.get[String]("d").toOption, None)
  }

  test("the public parameter names are allow-listed per key type") {
    assertEquals(Jwks.PublicParameters(Kty.Rsa), Set("n", "e"))
    assertEquals(Jwks.PublicParameters(Kty.Ec), Set("crv", "x", "y"))
    assertEquals(Jwks.PublicParameters(Kty.Okp), Set("crv", "x"))
    assertEquals(Jwks.PublicParameters.keySet, Kty.all)
  }

  test("an entry carries exactly the fixed fields and its allow-listed parameters") {
    val rendered = entries(Jwks(List(rsaKey, ecKey, okpKey)))
    val names = rendered.map(_.hcursor.keys.map(_.toSet).getOrElse(Set.empty[String]))
    assertEquals(
      names,
      List(
        fixed ++ Jwks.PublicParameters(Kty.Rsa),
        fixed ++ Jwks.PublicParameters(Kty.Ec),
        fixed ++ Jwks.PublicParameters(Kty.Okp)
      )
    )
  }

  test("a fixed field is rendered after the parameters so it is never overridden") {
    val entry = entries(Jwks(List(rsaKey))).head
    val names = entry.hcursor.keys.map(_.toList).getOrElse(Nil)
    assertEquals(names.takeRight(4), List(Jwks.FieldKid, Jwks.FieldKty, Jwks.FieldAlg, Jwks.FieldUse))
  }

  test("an empty document renders an empty key array") {
    assertEquals(entries(Jwks.empty), Nil)
  }
}
