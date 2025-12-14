package dev.oauth2.core

import cats.data.ValidatedNec
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class RevocationSpec extends ScalaCheckSuite {

  private val printable: Gen[String] =
    Gen.choose(1, 64).flatMap(n => Gen.listOfN(n, Gen.choose(0x21.toChar, 0x7e.toChar))).map(_.mkString)

  private val genToken: Gen[RevocationToken] =
    printable.map(raw => RevocationToken.from(raw).toOption.get)

  private def valid[A](decoded: ValidatedNec[OAuth2Error, A]): A =
    decoded.fold(errors => fail(errors.toChain.toList.map(_.code).mkString(",")), identity)

  private def errors[A](decoded: ValidatedNec[OAuth2Error, A]): List[OAuth2Error] =
    decoded.fold(_.toChain.toList, _ => Nil)

  private def revocation(extra: (String, String)*): ValidatedNec[OAuth2Error, RevocationRequest] =
    RevocationRequest.from(Map("token" -> "at-1") ++ extra)

  test("revocation request decodes a token without a hint") {
    val request = valid(revocation())
    assertEquals(request.token.value, "at-1")
    assertEquals(request.hint, None)
  }

  test("revocation request decodes both registered hints") {
    assertEquals(valid(revocation("token_type_hint" -> "access_token")).hint, Some(TokenTypeHint.AccessToken))
    assertEquals(
      valid(revocation("token_type_hint" -> "refresh_token")).hint,
      Some(TokenTypeHint.RefreshToken)
    )
  }

  test("revocation request refuses a missing token") {
    assertEquals(
      errors(RevocationRequest.from(Map.empty[String, String])).map(_.code),
      List("invalid_request")
    )
  }

  test("revocation request refuses an empty token") {
    assertEquals(errors(RevocationRequest.from(Map("token" -> ""))).map(_.code), List("invalid_request"))
  }

  test("revocation request refuses an unknown hint") {
    assertEquals(
      errors(revocation("token_type_hint" -> "id_token")).map(_.code),
      List("invalid_request")
    )
  }

  test("revocation request accumulates a missing token and an unknown hint") {
    assertEquals(
      errors(RevocationRequest.from(Map("token_type_hint" -> "nope"))).map(_.code),
      List("invalid_request", "invalid_request")
    )
  }

  test("the hint parses only the two registered values") {
    assertEquals(TokenTypeHint.from("access_token").toOption, Some(TokenTypeHint.AccessToken))
    assertEquals(TokenTypeHint.from("refresh_token").toOption, Some(TokenTypeHint.RefreshToken))
    assert(TokenTypeHint.from("Access_Token").isLeft)
  }

  test("a revocation token reads as an access and as a refresh token") {
    val token = RevocationToken.from("at-1").toOption.get
    assertEquals(RevocationToken.asAccessToken(token).map(_.value), Some("at-1"))
    assertEquals(RevocationToken.asRefreshToken(token).map(_.value), Some("at-1"))
  }

  test("a revocation token refuses a non printable value") {
    assert(RevocationToken.from("at\n1").isLeft)
    assert(RevocationToken.from("").isLeft)
  }

  property("a decoded revocation request keeps the token it was given") {
    forAll(genToken, Gen.oneOf(TokenTypeHint.all)) { (token, hint) =>
      val params = Map("token" -> token.value, "token_type_hint" -> hint.value)
      RevocationRequest.from(params).toOption == Some(RevocationRequest(token, Some(hint)))
    }
  }

  property("revocation without a hint is still valid") {
    forAll(genToken) { token =>
      RevocationRequest.from(Map("token" -> token.value)).toOption == Some(RevocationRequest(token, None))
    }
  }
}
