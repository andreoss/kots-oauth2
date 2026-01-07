package dev.oauth2.core

import java.time.Instant

import cats.data.ValidatedNec
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class IntrospectionSpec extends ScalaCheckSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val printable: Gen[String] =
    Gen.choose(1, 64).flatMap(n => Gen.listOfN(n, Gen.choose(0x21.toChar, 0x7e.toChar))).map(_.mkString)

  private val genToken: Gen[RevocationToken] =
    printable.map(raw => RevocationToken.from(raw).toOption.get)

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private def valid[A](decoded: ValidatedNec[OAuth2Error, A]): A =
    decoded.fold(errors => fail(errors.toChain.toList.map(_.code).mkString(",")), identity)

  private def errors[A](decoded: ValidatedNec[OAuth2Error, A]): List[OAuth2Error] =
    decoded.fold(_.toChain.toList, _ => Nil)

  private def introspection(extra: (String, String)*): ValidatedNec[OAuth2Error, IntrospectionRequest] =
    IntrospectionRequest.from(Map("token" -> "at-1") ++ extra)

  private def active: IntrospectionResponse =
    IntrospectionResponse.active(
      TokenTypeHint.AccessToken,
      unsafe(Scopes.parse("read")),
      unsafe(ClientId.from("client-1")),
      unsafe(Subject.from("user-1")),
      Start,
      Start.plusSeconds(3600L),
      Start
    )

  test("an introspection request decodes a token without a hint") {
    val request = valid(introspection())
    assertEquals(request.token.value, "at-1")
    assertEquals(request.hint, None)
  }

  test("an introspection request decodes both registered hints") {
    assertEquals(valid(introspection("token_type_hint" -> "access_token")).hint, Some(TokenTypeHint.AccessToken))
    assertEquals(valid(introspection("token_type_hint" -> "refresh_token")).hint, Some(TokenTypeHint.RefreshToken))
  }

  test("an introspection request refuses a missing token") {
    assertEquals(errors(IntrospectionRequest.from(Map.empty[String, String])).map(_.code), List("invalid_request"))
  }

  test("an introspection request refuses an unknown hint") {
    assertEquals(errors(introspection("token_type_hint" -> "id_token")).map(_.code), List("invalid_request"))
  }

  test("an introspection request accumulates every failure") {
    assertEquals(
      errors(IntrospectionRequest.from(Map("token_type_hint" -> "nope"))).map(_.code),
      List("invalid_request", "invalid_request")
    )
  }

  test("an inactive token is answered with the active flag alone") {
    val body = IntrospectionResponse.inactive.body
    assertEquals(body, Map("active" -> "false"))
    assert(!IntrospectionResponse.inactive.active)
  }

  test("an active token is answered with its metadata") {
    assert(active.active)
    assertEquals(
      active.body,
      Map(
        "active" -> "true",
        "scope" -> "read",
        "client_id" -> "client-1",
        "username" -> "user-1",
        "token_type" -> "Bearer",
        "exp" -> Start.plusSeconds(3600L).getEpochSecond.toString,
        "iat" -> Start.getEpochSecond.toString,
        "nbf" -> Start.getEpochSecond.toString,
        "sub" -> "user-1"
      )
    )
  }

  test("an active token without a scope answers no scope") {
    val body = IntrospectionResponse
      .active(TokenTypeHint.RefreshToken, Scopes.empty, unsafe(ClientId.from("client-1")), unsafe(Subject.from("user-1")), Start, Start, Start)
      .body
    assert(!body.contains("scope"))
    assertEquals(body("token_type"), "refresh_token")
  }

  property("a decoded introspection request keeps the token and the hint it was given") {
    forAll(genToken, Gen.oneOf(TokenTypeHint.all)) { (token, hint) =>
      val params = Map("token" -> token.value, "token_type_hint" -> hint.value)
      IntrospectionRequest.from(params).toOption == Some(IntrospectionRequest(token, Some(hint)))
    }
  }

  property("an active introspection body always carries the active flag") {
    forAll(genToken, Gen.oneOf(TokenTypeHint.all)) { (_, hint) =>
      IntrospectionResponse
        .active(hint, Scopes.empty, unsafe(ClientId.from("client-1")), unsafe(Subject.from("user-1")), Start, Start, Start)
        .body("active") == "true"
    }
  }
}
