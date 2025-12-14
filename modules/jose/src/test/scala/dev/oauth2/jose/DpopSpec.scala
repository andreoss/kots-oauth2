package dev.oauth2.jose

import java.time.Instant

import dev.oauth2.core.JwtId
import dev.oauth2.core.ParseFailure
import munit.FunSuite

class DpopSpec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A = Fakes.unsafe(parsed)

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def proof(
      jti: String = "proof-1",
      method: String = "POST",
      uri: String = "https://server.example/token",
      nonce: Option[String] = None
  ): String =
    Dpop
      .prove(
        Fakes.signingKey.alg,
        Fakes.signingPair.getPrivate,
        Fakes.signingJwk,
        unsafe(JwtId.from(jti)),
        method,
        uri,
        Start,
        nonce
      )
      .toOption
      .get

  test("a signed proof verifies with its embedded key") {
    val verified = Dpop.verify(proof()).toOption.get
    assertEquals(verified.method, "POST")
    assertEquals(verified.uri, "https://server.example/token")
    assertEquals(verified.jti.value, "proof-1")
    assertEquals(verified.issuedAt, Start)
    assertEquals(verified.nonce, None)
    assertEquals(Some(verified.thumbprint), Dpop.thumbprint(Fakes.signingJwk).toOption)
  }

  test("a proof carries its nonce") {
    assertEquals(Dpop.verify(proof(nonce = Some("n-1"))).toOption.get.nonce, Some("n-1"))
  }

  test("the rsa thumbprint matches the published vector") {
    val jwk = unsafe(
      Jwk.rsa(
        Fakes.keyId("vector"),
        Alg.RS256,
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "AQAB"
      )
    )
    assertEquals(
      Dpop.thumbprint(jwk).toOption.map(_.value),
      Some("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    )
  }

  test("a tampered or foreign proof is refused") {
    val compact = proof()
    assert(Dpop.verify(compact.dropRight(2) + "ab").isLeft)
    assert(Dpop.verify("not-a-proof").isLeft)
  }

  test("a jws without the dpop type is refused") {
    val plain = Jws
      .sign(Alg.RS256, Fakes.keyId("key-1"), Fakes.signingPair.getPrivate, """{"jti":"x"}""")
      .toOption
      .get
    assert(Dpop.verify(plain).isLeft)
  }
}
