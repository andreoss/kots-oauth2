package dev.oauth2.core

import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class NewtypeSpec extends ScalaCheckSuite {

  private val printable: Gen[String] =
    Gen.choose(1, 64).flatMap(n => Gen.listOfN(n, Gen.choose(0x21.toChar, 0x7e.toChar))).map(_.mkString)

  private val scopeToken: Gen[String] =
    Gen
      .choose(1, 32)
      .flatMap(n => Gen.listOfN(n, Gen.choose(0x21.toChar, 0x7e.toChar).suchThat(c => c != '"' && c != '\\')))
      .map(_.mkString)

  private val absoluteUri: Gen[String] =
    for {
      host <- Gen.choose(1, 12).flatMap(n => Gen.listOfN(n, Gen.alphaLowerChar)).map(_.mkString)
      path <- Gen.oneOf("", "/cb", "/a/b")
    } yield s"https://$host$path"

  private def roundTrip[A](
      name: String,
      gen: Gen[String],
      from: String => Either[ParseFailure, A],
      out: A => String
  ): Unit =
    property(s"$name round trips") {
      forAll(gen) { raw =>
        from(raw).map(out) == Right(raw)
      }
    }

  roundTrip[ClientId]("ClientId", printable, ClientId.from, _.value)
  roundTrip[GrantId]("GrantId", printable, GrantId.from, _.value)
  roundTrip[KeyId]("KeyId", printable, KeyId.from, _.value)
  roundTrip[Subject]("Subject", printable, Subject.from, _.value)
  roundTrip[AuthorizationCode]("AuthorizationCode", printable, AuthorizationCode.from, _.value)
  roundTrip[AccessToken]("AccessToken", printable, AccessToken.from, _.value)
  roundTrip[RefreshToken]("RefreshToken", printable, RefreshToken.from, _.value)
  roundTrip[Issuer]("Issuer", absoluteUri, Issuer.from, _.value)
  roundTrip[RedirectUri]("RedirectUri", absoluteUri, RedirectUri.from, _.value)
  roundTrip[ResourceIndicator]("ResourceIndicator", absoluteUri, ResourceIndicator.from, _.value)
  roundTrip[Scope]("Scope", scopeToken, Scope.from, _.value)

  property("Scopes round trips") {
    forAll(Gen.listOf(scopeToken)) { raws =>
      Scopes.from(raws).map(_.value.map(_.value)) == Right(raws.toSet)
    }
  }

  test("empty values are refused") {
    assertEquals(ClientId.from(""), Left(ParseFailure("ClientId", "empty")))
    assertEquals(Scope.from(""), Left(ParseFailure("Scope", "empty")))
  }

  test("values with spaces or non printable characters are refused") {
    assertEquals(AccessToken.from("a b").isLeft, true)
    assertEquals(RefreshToken.from("a\u0000b").isLeft, true)
    assertEquals(AuthorizationCode.from("ю").isLeft, true)
  }

  test("values over the length bound are refused") {
    val raw = "a" * (Text.MaxLength + 1)
    assert(Subject.from(raw).isLeft)
  }

  test("an access token accepts a compact jwt length and stays bounded") {
    assert(AccessToken.from("a" * (Text.MaxLength + 1)).isRight)
    assert(AccessToken.from("a" * Text.TokenMaxLength).isRight)
    assert(AccessToken.from("a" * (Text.TokenMaxLength + 1)).isLeft)
  }

  test("scope tokens refuse quote and backslash") {
    assert(Scope.from("a\"b").isLeft)
    assert(Scope.from("a\\b").isLeft)
  }

  test("issuer requires https and refuses query and fragment") {
    assertEquals(Issuer.from("http://example.com").isLeft, true)
    assertEquals(Issuer.from("https://example.com?a=b").isLeft, true)
    assertEquals(Issuer.from("https://example.com#f").isLeft, true)
  }

  test("redirect uri and resource indicator refuse fragments and relative references") {
    assertEquals(RedirectUri.from("https://example.com/cb#f").isLeft, true)
    assertEquals(RedirectUri.from("/cb").isLeft, true)
    assertEquals(ResourceIndicator.from("https://api.example.com#f").isLeft, true)
    assertEquals(ResourceIndicator.from("cb").isLeft, true)
  }

  test("redirect uri matching is exact") {
    val registered = Set(RedirectUri.from("https://example.com/cb").toOption.get)
    val candidate = RedirectUri.from("https://example.com/cb").toOption.get
    val other = RedirectUri.from("https://example.com/cb/extra").toOption.get
    assertEquals(RedirectUri.exactMatch(registered, candidate), true)
    assertEquals(RedirectUri.exactMatch(registered, other), false)
  }
}
