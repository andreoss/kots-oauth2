package dev.oauth2.jose

import dev.oauth2.core.KeyId
import dev.oauth2.core.ParseFailure
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class KeysSpec extends ScalaCheckSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val kid: KeyId = unsafe(KeyId.from("key-1"))

  private val other: KeyId = unsafe(KeyId.from("key-2"))

  private val n: String = "t6Q8SWSFZkG9s2Y0m1IuA"

  private val e: String = "AQAB"

  private val x: String = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"

  private val y: String = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

  test("the algorithm allow-list accepts asymmetric signature algorithms only") {
    assertEquals(Alg.from("RS256"), Right(Alg.RS256))
    assertEquals(Alg.from("ES256"), Right(Alg.ES256))
    assertEquals(Alg.from("EdDSA"), Right(Alg.EdDSA))
  }

  test("the algorithm allow-list refuses none, mac and other algorithms") {
    assertEquals(Alg.from("none").isLeft, true)
    assertEquals(Alg.from("HS256").isLeft, true)
    assertEquals(Alg.from("RS512").isLeft, true)
    assertEquals(Alg.from("").isLeft, true)
  }

  test("every algorithm carries the key type it belongs to") {
    assertEquals(Alg.RS256.kty, Kty.Rsa)
    assertEquals(Alg.ES256.kty, Kty.Ec)
    assertEquals(Alg.EdDSA.kty, Kty.Okp)
  }

  test("an rsa key carries its identifier, algorithm, key type and public parameters") {
    val key = unsafe(Jwk.rsa(kid, Alg.RS256, n, e))
    assertEquals(key.kid, kid)
    assertEquals(key.alg, Alg.RS256)
    assertEquals(key.kty, Kty.Rsa)
    assertEquals(key.parameters, Map("n" -> n, "e" -> e))
  }

  test("an ec key carries its curve and both coordinates") {
    val key = unsafe(Jwk.ec(kid, Alg.ES256, "P-256", x, y))
    assertEquals(key.kty, Kty.Ec)
    assertEquals(key.parameters, Map("crv" -> "P-256", "x" -> x, "y" -> y))
  }

  test("an okp key carries its curve and one coordinate") {
    val key = unsafe(Jwk.okp(kid, Alg.EdDSA, "Ed25519", x))
    assertEquals(key.kty, Kty.Okp)
    assertEquals(key.parameters, Map("crv" -> "Ed25519", "x" -> x))
  }

  test("an algorithm is refused on a key of another type") {
    assertEquals(Jwk.rsa(kid, Alg.ES256, n, e).isLeft, true)
    assertEquals(Jwk.rsa(kid, Alg.EdDSA, n, e).isLeft, true)
    assertEquals(Jwk.ec(kid, Alg.RS256, "P-256", x, y).isLeft, true)
    assertEquals(Jwk.okp(kid, Alg.ES256, "P-256", x).isLeft, true)
  }

  test("a curve that does not match the algorithm is refused") {
    assertEquals(Jwk.ec(kid, Alg.ES256, "P-384", x, y).isLeft, true)
    assertEquals(Jwk.ec(kid, Alg.ES256, "Ed25519", x, y).isLeft, true)
    assertEquals(Jwk.okp(kid, Alg.EdDSA, "P-256", x).isLeft, true)
    assertEquals(Jwk.okp(kid, Alg.EdDSA, "X25519", x).isLeft, true)
  }

  test("a public parameter must be base64url") {
    assertEquals(Jwk.rsa(kid, Alg.RS256, "", e).isLeft, true)
    assertEquals(Jwk.rsa(kid, Alg.RS256, "a+b", e).isLeft, true)
    assertEquals(Jwk.ec(kid, Alg.ES256, "P-256", "a/b", y).isLeft, true)
    assertEquals(Jwk.okp(kid, Alg.EdDSA, "Ed25519", "a=b").isLeft, true)
  }

  test("a key is found by its identifier and not by another one") {
    val keys = Jwks(List(unsafe(Jwk.rsa(kid, Alg.RS256, n, e))))
    assertEquals(keys.find(kid).map(_.kty), Some(Kty.Rsa))
    assertEquals(keys.find(other), None)
    assertEquals(Jwks.empty.keys, Nil)
  }

  test("an empty key identifier is refused") {
    assertEquals(KeyId.from("").isLeft, true)
  }

  property("every allowed algorithm round trips") {
    forAll(Gen.oneOf(Alg.allowed.toSeq)) { alg =>
      Alg.from(alg.value) == Right(alg) && Kty.from(alg.kty.value) == Right(alg.kty)
    }
  }

  property("an algorithm outside the allow-list is refused") {
    forAll(Gen.alphaNumStr.suchThat(raw => !Alg.allowed.exists(_.value == raw))) { raw =>
      Alg.from(raw).isLeft
    }
  }
}
