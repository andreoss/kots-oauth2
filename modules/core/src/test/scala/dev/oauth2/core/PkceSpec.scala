package dev.oauth2.core

import org.scalacheck.Gen
import org.scalacheck.Prop._
import munit.ScalaCheckSuite

class PkceSpec extends ScalaCheckSuite {

  private val ExampleVerifier: String = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

  private val ExampleChallenge: String = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  private val OtherVerifier: String = "~vjfKQEFmDCOvyYAoUcxYCLkKmQTWyaWvGXFKcUwUfHk"

  private val verifierChar: Gen[Char] =
    Gen.oneOf(Gen.alphaNumChar, Gen.oneOf('-', '.', '_', '~'))

  private val verifierText: Gen[String] =
    Gen
      .choose(CodeVerifier.MinLength, CodeVerifier.MaxLength)
      .flatMap(n => Gen.listOfN(n, verifierChar))
      .map(_.mkString)

  private val verifiers: Gen[CodeVerifier] =
    verifierText.map(raw => CodeVerifier.from(raw).toOption.get)

  private val s256: Pkce =
    Pkce(CodeChallenge.from(ExampleChallenge).toOption.get, CodeChallengeMethod.S256)

  private def codeOf(result: Either[OAuth2Error, Unit]): String =
    result.left.toOption.map(_.code).getOrElse("accepted")

  test("S256 verification accepts the example of RFC 7636") {
    val verifier = CodeVerifier.from(ExampleVerifier).toOption.get
    assertEquals(Pkce.verify(s256, verifier), Right(()))
  }

  test("a derived challenge is the RFC 7636 example and verifies its verifier") {
    val verifier = CodeVerifier.from(ExampleVerifier).toOption.get
    val derived = Pkce.challenge(verifier).toOption.get
    assertEquals(derived.value, ExampleChallenge)
    assertEquals(Pkce.verify(Pkce(derived, CodeChallengeMethod.S256), verifier), Right(()))
  }

  test("S256 verification refuses another verifier") {
    val verifier = CodeVerifier.from(OtherVerifier).toOption.get
    assert(Pkce.verify(s256, verifier).isLeft)
  }

  test("S256 verification failure is invalid_grant") {
    val verifier = CodeVerifier.from(OtherVerifier).toOption.get
    assertEquals(codeOf(Pkce.verify(s256, verifier)), "invalid_grant")
  }

  test("plain verification is refused") {
    val verifier = CodeVerifier.from(ExampleVerifier).toOption.get
    val challenge = CodeChallenge.from(ExampleVerifier).toOption.get
    assert(Pkce.verify(Pkce(challenge, CodeChallengeMethod.Plain), verifier).isLeft)
  }

  test("plain refusal is invalid_grant") {
    val verifier = CodeVerifier.from(ExampleVerifier).toOption.get
    val challenge = CodeChallenge.from(ExampleVerifier).toOption.get
    assertEquals(codeOf(Pkce.verify(Pkce(challenge, CodeChallengeMethod.Plain), verifier)), "invalid_grant")
  }

  test("the example verifier parses") {
    assert(CodeVerifier.from(ExampleVerifier).isRight)
  }

  property("S256 verification refuses every other verifier") {
    forAll(verifiers) { verifier =>
      verifier.value == ExampleVerifier || Pkce.verify(s256, verifier).isLeft
    }
  }

  property("S256 verification refuses a challenge that is not the computed one") {
    forAll(verifiers) { verifier =>
      verifier.value == ExampleVerifier ||
      Pkce.verify(Pkce(CodeChallenge.from(verifier.value).toOption.get, CodeChallengeMethod.S256), verifier).isLeft
    }
  }
}
