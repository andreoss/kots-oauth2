package kots.oauth2.jose

import kots.oauth2.core.KeyId
import kots.oauth2.jose.Fakes.unsafe
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class KeysSpec extends ScalaCheckSuite {

  private val kid: KeyId = Fakes.keyId("key-1")

  private val other: KeyId = Fakes.keyId("key-2")

  private val n: String = Fakes.Modulus

  private val e: String = Fakes.Exponent

  private val x: String = Fakes.X

  private val y: String = Fakes.Y

  test("every fixture parameter is decodable base64url") {
    val decoder = java.util.Base64.getUrlDecoder
    List(n, e, x, y).foreach(parameter => assert(decoder.decode(parameter).nonEmpty))
  }

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

  test("every allowed algorithm is a signature algorithm") {
    assert(Alg.allowed.forall(_.use == Use.Sig))
  }

  test("a key carries the use of its algorithm") {
    assertEquals(Fakes.rsa("key-1").use, Use.Sig)
    assertEquals(Fakes.ec("key-2").use, Use.Sig)
    assertEquals(Fakes.okp("key-3").use, Use.Sig)
  }

  test("a use is parsed from its wire value and refused otherwise") {
    assertEquals(Use.from("sig"), Right(Use.Sig))
    assertEquals(Use.from("enc"), Right(Use.Enc))
    assertEquals(Use.from("mac").isLeft, true)
    assertEquals(Use.from("").isLeft, true)
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

  test("a public parameter whose length cannot decode is refused") {
    assertEquals(Jwk.rsa(kid, Alg.RS256, "t6Q8SWSFZkG9s2Y0m1IuA", e).isLeft, true)
    assertEquals(Jwk.rsa(kid, Alg.RS256, n, "AQABA").isLeft, true)
    assertEquals(Jwk.ec(kid, Alg.ES256, "P-256", "abcde", y).isLeft, true)
    assertEquals(Jwk.okp(kid, Alg.EdDSA, "Ed25519", "a").isLeft, true)
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
