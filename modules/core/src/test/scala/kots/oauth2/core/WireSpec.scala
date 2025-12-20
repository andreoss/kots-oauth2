package kots.oauth2.core

import org.scalacheck.Gen
import org.scalacheck.Prop._
import munit.ScalaCheckSuite

class WireSpec extends ScalaCheckSuite {

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

  private val verifier: Gen[String] =
    Gen
      .choose(CodeVerifier.MinLength, CodeVerifier.MaxLength)
      .flatMap(n =>
        Gen.listOfN(
          n,
          Gen.oneOf(Gen.alphaNumChar, Gen.oneOf('-', '.', '_', '~'))
        )
      )
      .map(_.mkString)

  private val scopes: Gen[Scopes] =
    Gen.listOf(scopeToken).map(raws => Scopes.of(raws.distinct.flatMap(Scope.from(_).toOption)))

  private def roundTrip[A: Wire](name: String, gen: Gen[A]): Unit =
    property(s"$name wire round trips") {
      forAll(gen) { value =>
        Wire[A].decode(Wire[A].encode(value)) == Right(value)
      }
    }

  private def stability[A: Wire](name: String, gen: Gen[String]): Unit =
    property(s"$name wire encoding is stable") {
      forAll(gen) { raw =>
        Wire[A].decode(raw).map(Wire[A].encode) match {
          case Right(encoded) => Wire[A].decode(encoded).map(Wire[A].encode) == Right(encoded)
          case Left(_)        => true
        }
      }
    }

  private def refuses[A: Wire](name: String, raw: String): Unit =
    test(s"$name wire decoding refuses $raw") {
      assert(Wire[A].decode(raw).isLeft)
    }

  roundTrip[ClientId]("ClientId", printable.map(raw => ClientId.from(raw).toOption.get))
  roundTrip[Subject]("Subject", printable.map(raw => Subject.from(raw).toOption.get))
  roundTrip[GrantId]("GrantId", printable.map(raw => GrantId.from(raw).toOption.get))
  roundTrip[State]("State", printable.map(raw => State.from(raw).toOption.get))
  roundTrip[AuthorizationCode](
    "AuthorizationCode",
    printable.map(raw => AuthorizationCode.from(raw).toOption.get)
  )
  roundTrip[AccessToken]("AccessToken", printable.map(raw => AccessToken.from(raw).toOption.get))
  roundTrip[RefreshToken]("RefreshToken", printable.map(raw => RefreshToken.from(raw).toOption.get))
  roundTrip[Scope]("Scope", scopeToken.map(raw => Scope.from(raw).toOption.get))
  roundTrip[Issuer]("Issuer", absoluteUri.map(raw => Issuer.from(raw).toOption.get))
  roundTrip[RedirectUri]("RedirectUri", absoluteUri.map(raw => RedirectUri.from(raw).toOption.get))
  roundTrip[ResourceIndicator](
    "ResourceIndicator",
    absoluteUri.map(raw => ResourceIndicator.from(raw).toOption.get)
  )
  roundTrip[CodeVerifier]("CodeVerifier", verifier.map(raw => CodeVerifier.from(raw).toOption.get))
  roundTrip[CodeChallenge]("CodeChallenge", verifier.map(raw => CodeChallenge.from(raw).toOption.get))
  roundTrip[CodeChallengeMethod]("CodeChallengeMethod", Gen.oneOf(CodeChallengeMethod.all))
  roundTrip[AuthorizationDetailType](
    "AuthorizationDetailType",
    printable.map(raw => AuthorizationDetailType.from(raw).toOption.get)
  )
  roundTrip[Location]("Location", absoluteUri.map(raw => Location.from(raw).toOption.get))
  roundTrip[Action]("Action", printable.map(raw => Action.from(raw).toOption.get))
  roundTrip[Scopes]("Scopes", scopes)
  roundTrip[ResponseType]("ResponseType", Gen.oneOf(ResponseType.all))
  roundTrip[GrantType]("GrantType", Gen.oneOf(GrantType.all))
  roundTrip[ClientAuthMethod]("ClientAuthMethod", Gen.oneOf(ClientAuthMethod.all))
  roundTrip[RevocationToken]("RevocationToken", printable.map(raw => RevocationToken.from(raw).toOption.get))
  roundTrip[TokenTypeHint]("TokenTypeHint", Gen.oneOf(TokenTypeHint.all))

  stability[ClientId]("ClientId", printable)
  stability[Scopes]("Scopes", Gen.listOf(scopeToken).map(_.mkString(" ")))
  stability[CodeChallengeMethod]("CodeChallengeMethod", Gen.alphaLowerStr)

  property("Scopes wire encoding is sorted and space separated") {
    forAll(scopes) { value =>
      val encoded = Wire[Scopes].encode(value)
      encoded.split(" ", -1).toVector == encoded.split(" ", -1).toVector.sorted
    }
  }

  test("Scopes wire decoding of the empty text is the empty set") {
    assertEquals(Wire[Scopes].decode(""), Right(Scopes.empty))
  }

  test("Scopes wire decoding refuses repeated delimiters") {
    assert(Wire[Scopes].decode("openid  profile").isLeft)
  }

  refuses[ClientId]("ClientId", "")
  refuses[Scope]("Scope", "")
  refuses[Issuer]("Issuer", "https://example.com/?a=b")
  refuses[CodeChallengeMethod]("CodeChallengeMethod", "none")
  refuses[CodeVerifier]("CodeVerifier", "short")
  refuses[ResponseType]("ResponseType", "token")
  refuses[GrantType]("GrantType", "password")
  refuses[TokenTypeHint]("TokenTypeHint", "id_token")
  refuses[RevocationToken]("RevocationToken", "")
}
