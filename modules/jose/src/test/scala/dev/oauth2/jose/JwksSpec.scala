package dev.oauth2.jose

import dev.oauth2.core.KeyId
import dev.oauth2.core.ParseFailure
import munit.FunSuite

class JwksSpec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val kid: KeyId = unsafe(KeyId.from("key-1"))

  private val n: String = "t6Q8SWSFZkG9s2Y0m1IuA"

  private val e: String = "AQAB"

  private val x: String = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"

  private val y: String = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

  private val rsaKey: Jwk = unsafe(Jwk.rsa(kid, Alg.RS256, n, e))

  private val ecKey: Jwk = unsafe(Jwk.ec(unsafe(KeyId.from("key-2")), Alg.ES256, "P-256", x, y))

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

  test("an empty document renders an empty key array") {
    assertEquals(entries(Jwks.empty), Nil)
  }
}
