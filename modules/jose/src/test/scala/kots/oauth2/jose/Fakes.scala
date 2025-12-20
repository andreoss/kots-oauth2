package kots.oauth2.jose

import kots.oauth2.core.KeyId
import kots.oauth2.core.ParseFailure

object Fakes {

  def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(failure => sys.error(failure.toString), identity)

  val Modulus: String =
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

  val Exponent: String = "AQAB"

  val X: String = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"

  val Y: String = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

  def keyId(value: String): KeyId = unsafe(KeyId.from(value))

  lazy val signingPair: java.security.KeyPair = {
    val generator = java.security.KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator.generateKeyPair
  }

  lazy val signingJwk: Jwk = {
    val public = signingPair.getPublic.asInstanceOf[java.security.interfaces.RSAPublicKey]
    def parameter(value: java.math.BigInteger): String =
      java.util.Base64.getUrlEncoder.withoutPadding.encodeToString(value.toByteArray.dropWhile(_ == 0))
    unsafe(
      Jwk.rsa(keyId("key-1"), Alg.RS256, parameter(public.getModulus), parameter(public.getPublicExponent))
    )
  }

  lazy val signingKey: SigningKey = SigningKey(keyId("key-1"), Alg.RS256, signingPair.getPrivate)

  def rsa(kid: String): Jwk = unsafe(Jwk.rsa(keyId(kid), Alg.RS256, Modulus, Exponent))

  def ec(kid: String): Jwk = unsafe(Jwk.ec(keyId(kid), Alg.ES256, "P-256", X, Y))

  def okp(kid: String): Jwk = unsafe(Jwk.okp(keyId(kid), Alg.EdDSA, "Ed25519", X))
}
