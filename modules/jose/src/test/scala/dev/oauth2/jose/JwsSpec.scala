package dev.oauth2.jose

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

import dev.oauth2.core.KeyId
import munit.FunSuite

class JwsSpec extends FunSuite {

  private val encoder: Base64.Encoder = Base64.getUrlEncoder.withoutPadding

  private def unsignedBytes(value: BigInteger): Array[Byte] =
    value.toByteArray.dropWhile(_ == 0)

  private def fixed(value: BigInteger, size: Int): Array[Byte] = {
    val raw = unsignedBytes(value)
    Array.fill[Byte](size - raw.length)(0) ++ raw
  }

  private def parameter(raw: Array[Byte]): String = encoder.encodeToString(raw)

  private val kid: KeyId = Fakes.keyId("key-1")

  private lazy val rsaPair: KeyPair = {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator.generateKeyPair
  }

  private lazy val rsaJwk: Jwk = {
    val public = rsaPair.getPublic.asInstanceOf[RSAPublicKey]
    Fakes.unsafe(
      Jwk.rsa(
        kid,
        Alg.RS256,
        parameter(unsignedBytes(public.getModulus)),
        parameter(unsignedBytes(public.getPublicExponent))
      )
    )
  }

  private lazy val ecPair: KeyPair = {
    val generator = KeyPairGenerator.getInstance("EC")
    generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"))
    generator.generateKeyPair
  }

  private lazy val ecJwk: Jwk = {
    val public = ecPair.getPublic.asInstanceOf[ECPublicKey]
    Fakes.unsafe(
      Jwk.ec(
        kid,
        Alg.ES256,
        "P-256",
        parameter(fixed(public.getW.getAffineX, 32)),
        parameter(fixed(public.getW.getAffineY, 32))
      )
    )
  }

  private lazy val okpPair: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair

  private lazy val okpJwk: Jwk = {
    val public = okpPair.getPublic.asInstanceOf[EdECPublicKey]
    val little = fixed(public.getPoint.getY, 32).reverse
    if (public.getPoint.isXOdd) little(31) = (little(31) | 0x80).toByte
    Fakes.unsafe(Jwk.okp(kid, Alg.EdDSA, "Ed25519", parameter(little)))
  }

  private val payload: String = """{"sub":"user-1"}"""

  test("a signed jws has three base64url segments and a typed header") {
    val compact = Jws.sign(Alg.RS256, kid, rsaPair.getPrivate, payload).toOption.get
    val segments = compact.split('.')
    assertEquals(segments.length, 3)
    val header = new String(Base64.getUrlDecoder.decode(segments(0)), "UTF-8")
    val cursor = io.circe.parser.parse(header).toOption.get.hcursor
    assertEquals(cursor.get[String]("alg").toOption, Some("RS256"))
    assertEquals(cursor.get[String]("kid").toOption, Some("key-1"))
    assertEquals(cursor.get[String]("typ").toOption, Some("JWT"))
  }

  test("every allowed algorithm signs and verifies against its published key") {
    List(
      (Alg.RS256: Alg, rsaPair, rsaJwk),
      (Alg.ES256: Alg, ecPair, ecJwk),
      (Alg.EdDSA: Alg, okpPair, okpJwk)
    ).foreach { case (alg, pair, jwk) =>
      val compact = Jws.sign(alg, kid, pair.getPrivate, payload).toOption.get
      assertEquals(Jws.verify(compact, Jwks(List(jwk))), Right(payload))
    }
  }

  test("a tampered payload is refused") {
    val compact = Jws.sign(Alg.RS256, kid, rsaPair.getPrivate, payload).toOption.get
    val segments = compact.split('.')
    val forged =
      segments(0) + "." + encoder.encodeToString("""{"sub":"user-2"}""".getBytes("UTF-8")) + "." + segments(2)
    assert(Jws.verify(forged, Jwks(List(rsaJwk))).isLeft)
  }

  test("a jws without a published key for its kid is refused") {
    val compact = Jws.sign(Alg.RS256, kid, rsaPair.getPrivate, payload).toOption.get
    assert(Jws.verify(compact, Jwks.empty).isLeft)
  }

  test("a jws whose header algorithm differs from the published key is refused") {
    val compact = Jws.sign(Alg.RS256, kid, rsaPair.getPrivate, payload).toOption.get
    assert(Jws.verify(compact, Jwks(List(ecJwk))).isLeft)
  }

  test("a signature by another key is refused") {
    val stranger = {
      val generator = KeyPairGenerator.getInstance("RSA")
      generator.initialize(2048)
      generator.generateKeyPair
    }
    val compact = Jws.sign(Alg.RS256, kid, stranger.getPrivate, payload).toOption.get
    assert(Jws.verify(compact, Jwks(List(rsaJwk))).isLeft)
  }

  test("a malformed compact form is refused") {
    assert(Jws.verify("only.two", Jwks(List(rsaJwk))).isLeft)
    assert(Jws.verify("", Jwks(List(rsaJwk))).isLeft)
    assert(Jws.verify("a.b.c", Jwks(List(rsaJwk))).isLeft)
  }

  test("signing with a key of the wrong type is refused") {
    assert(Jws.sign(Alg.RS256, kid, ecPair.getPrivate, payload).isLeft)
  }
}
