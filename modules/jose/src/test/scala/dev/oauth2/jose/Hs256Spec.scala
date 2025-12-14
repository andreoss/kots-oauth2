package dev.oauth2.jose

import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ParseFailure
import munit.FunSuite

class Hs256Spec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A = Fakes.unsafe(parsed)

  private val secret: ClientSecret = unsafe(ClientSecret.from("s3cret"))

  private val payload: String = """{"sub":"client-1"}"""

  test("a mac signed compact verifies with the shared secret") {
    assertEquals(Hs256.verify(Hs256.sign(secret, payload), secret), Right(payload))
  }

  test("a tampered compact or another secret is refused") {
    val compact = Hs256.sign(secret, payload)
    val tampered = compact.dropRight(2) + "ab"
    assert(Hs256.verify(tampered, secret).isLeft)
    assert(Hs256.verify(compact, unsafe(ClientSecret.from("other"))).isLeft)
  }

  test("an asymmetrically signed compact is refused by the mac verifier") {
    val compact = Jws
      .sign(Alg.RS256, Fakes.keyId("key-1"), Fakes.signingPair.getPrivate, payload)
      .toOption
      .get
    assert(Hs256.verify(compact, secret).isLeft)
  }

  test("a malformed compact is refused") {
    assert(Hs256.verify("not-a-jws", secret).isLeft)
    assert(Hs256.verify("a.b.c", secret).isLeft)
  }
}
