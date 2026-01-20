package kots.oauth2.core

import org.scalacheck.Gen
import org.scalacheck.Prop._

import munit.ScalaCheckSuite

class TokenHashSpec extends ScalaCheckSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val token: Gen[String] =
    Gen.choose(1, 64).flatMap(n => Gen.listOfN(n, Gen.choose(0x21.toChar, 0x7e.toChar))).map(_.mkString)

  private val access: AccessToken = unsafe(AccessToken.from("at-1"))

  private val refresh: RefreshToken = unsafe(RefreshToken.from("rt-1"))

  test("an access token hash verifies its token") {
    assert(AccessTokenHash.verify(AccessTokenHash.of(access), access))
  }

  test("a refresh token hash verifies its token") {
    assert(RefreshTokenHash.verify(RefreshTokenHash.of(refresh), refresh))
  }

  test("an access token hash is not the token") {
    assertNotEquals(AccessTokenHash.of(access).value, access.value)
  }

  test("a refresh token hash is not the token") {
    assertNotEquals(RefreshTokenHash.of(refresh).value, refresh.value)
  }

  test("a token hash is 64 hex characters") {
    assertEquals(AccessTokenHash.of(access).value.length, 64)
    assertEquals(RefreshTokenHash.of(refresh).value.length, 64)
    assert(AccessTokenHash.of(access).value.forall(char => char.isDigit || "abcdef".contains(char)))
  }

  test("a token hash is deterministic") {
    assertEquals(AccessTokenHash.of(access), AccessTokenHash.of(access))
    assertEquals(RefreshTokenHash.of(refresh), RefreshTokenHash.of(refresh))
  }

  property("an access token hash refuses every other token") {
    forAll(token) { raw =>
      val other = AccessToken.from(raw).toOption
      other.isEmpty || raw == access.value || !AccessTokenHash.verify(AccessTokenHash.of(access), other.get)
    }
  }

  property("a refresh token hash refuses every other token") {
    forAll(token) { raw =>
      val other = RefreshToken.from(raw).toOption
      other.isEmpty || raw == refresh.value || !RefreshTokenHash.verify(
        RefreshTokenHash.of(refresh),
        other.get
      )
    }
  }
}
