package kots.oauth2.http

import kots.oauth2.jose.Fakes
import kots.oauth2.jose.Jwk
import kots.oauth2.jose.Jwks
import kots.oauth2.jose.Kty
import munit.FunSuite

class JwkSetSpec extends FunSuite {

  private val n: String = Fakes.Modulus

  private val e: String = Fakes.Exponent

  private val rsaKey: Jwk = Fakes.rsa("key-1")

  private val ecKey: Jwk = Fakes.ec("key-2")

  private val okpKey: Jwk = Fakes.okp("key-3")

  private val fixed: Set[String] = Set(JwkSet.FieldKid, JwkSet.FieldKty, JwkSet.FieldAlg, JwkSet.FieldUse)

  private def entries(document: Jwks): List[io.circe.Json] =
    JwkSet
      .render(document)
      .getOrElse(JwkSet.FieldKeys, fail(s"no ${JwkSet.FieldKeys} array in the document"))
      .asArray
      .getOrElse(fail(s"no ${JwkSet.FieldKeys} array in the document"))
      .toList

  private def field(entry: io.circe.Json, name: String): String =
    entry.hcursor.get[String](name).getOrElse(fail(s"no $name in $entry"))

  test("a document renders one entry per key") {
    val rendered = entries(Jwks(List(rsaKey, ecKey)))
    assertEquals(rendered.length, 2)
    assertEquals(rendered.map(field(_, JwkSet.FieldKid)), List("key-1", "key-2"))
    assertEquals(rendered.map(field(_, JwkSet.FieldKty)), List("RSA", "EC"))
    assertEquals(rendered.map(field(_, JwkSet.FieldAlg)), List("RS256", "ES256"))
    assertEquals(rendered.map(field(_, JwkSet.FieldUse)), List("sig", "sig"))
  }

  test("an entry carries the public parameters of its key type") {
    val entry = entries(Jwks(List(rsaKey))).head
    assertEquals(field(entry, "n"), n)
    assertEquals(field(entry, "e"), e)
    assertEquals(entry.hcursor.keys.map(_.toSet), Some(fixed ++ JwkSet.PublicParameters(Kty.Rsa)))
  }

  test("the public parameter names are allow-listed per key type") {
    assertEquals(JwkSet.PublicParameters(Kty.Rsa), Set("n", "e"))
    assertEquals(JwkSet.PublicParameters(Kty.Ec), Set("crv", "x", "y"))
    assertEquals(JwkSet.PublicParameters(Kty.Okp), Set("crv", "x"))
    assertEquals(JwkSet.PublicParameters.keySet, Kty.all)
  }

  test("an entry carries exactly the fixed fields and its allow-listed parameters") {
    val rendered = entries(Jwks(List(rsaKey, ecKey, okpKey)))
    val names = rendered.map(_.hcursor.keys.map(_.toSet).getOrElse(Set.empty[String]))
    assertEquals(
      names,
      List(
        fixed ++ JwkSet.PublicParameters(Kty.Rsa),
        fixed ++ JwkSet.PublicParameters(Kty.Ec),
        fixed ++ JwkSet.PublicParameters(Kty.Okp)
      )
    )
  }

  test("a fixed field is rendered after the parameters so it is never overridden") {
    val entry = entries(Jwks(List(rsaKey))).head
    val names = entry.hcursor.keys.map(_.toList).getOrElse(Nil)
    assertEquals(names.takeRight(4), List(JwkSet.FieldKid, JwkSet.FieldKty, JwkSet.FieldAlg, JwkSet.FieldUse))
  }

  test("an empty document renders an empty key array") {
    assertEquals(entries(Jwks.empty), Nil)
  }
}
