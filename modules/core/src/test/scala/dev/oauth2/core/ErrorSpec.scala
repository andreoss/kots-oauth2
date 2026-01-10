package dev.oauth2.core

import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class ErrorSpec extends ScalaCheckSuite {

  private val genError: Gen[OAuth2Error] = {
    val desc = Gen.option(Gen.alphaNumStr)
    val uri = Gen.option(Gen.const("https://example.com/errors/1"))
    val base = for {
      d <- desc
      u <- uri
    } yield (d, u)
    val cases: List[(Option[String], Option[String]) => OAuth2Error] = List(
      (d, u) => OAuth2Error.InvalidRequest(d, u),
      (d, u) => OAuth2Error.InvalidClient(d, u),
      (d, u) => OAuth2Error.InvalidGrant(d, u),
      (d, u) => OAuth2Error.UnauthorizedClient(d, u),
      (d, u) => OAuth2Error.UnsupportedGrantType(d, u),
      (d, u) => OAuth2Error.InvalidScope(d, u),
      (d, u) => OAuth2Error.AccessDenied(d, u),
      (d, u) => OAuth2Error.UnsupportedResponseType(d, u),
      (d, u) => OAuth2Error.ServerError(d, u),
      (d, u) => OAuth2Error.TemporarilyUnavailable(d, u),
      (d, u) => OAuth2Error.AuthorizationPending(d, u),
      (d, u) => OAuth2Error.SlowDown(d, u),
      (d, u) => OAuth2Error.ExpiredToken(d, u)
    )
    for {
      f <- Gen.oneOf(cases)
      tu <- base
    } yield f(tu._1, tu._2)
  }

  test("every device grant error carries the RFC 8628 code and a bad request status") {
    assertEquals(OAuth2Error.AuthorizationPending().code, "authorization_pending")
    assertEquals(OAuth2Error.SlowDown().code, "slow_down")
    assertEquals(OAuth2Error.ExpiredToken().code, "expired_token")
    assertEquals(OAuth2Error.AuthorizationPending().status, 400)
    assertEquals(OAuth2Error.SlowDown().status, 400)
    assertEquals(OAuth2Error.ExpiredToken().status, 400)
  }

  test("every error carries the RFC 6749 code") {
    assertEquals(OAuth2Error.InvalidRequest().code, "invalid_request")
    assertEquals(OAuth2Error.InvalidClient().code, "invalid_client")
    assertEquals(OAuth2Error.InvalidGrant().code, "invalid_grant")
    assertEquals(OAuth2Error.UnauthorizedClient().code, "unauthorized_client")
    assertEquals(OAuth2Error.UnsupportedGrantType().code, "unsupported_grant_type")
    assertEquals(OAuth2Error.InvalidScope().code, "invalid_scope")
    assertEquals(OAuth2Error.AccessDenied().code, "access_denied")
    assertEquals(OAuth2Error.UnsupportedResponseType().code, "unsupported_response_type")
    assertEquals(OAuth2Error.ServerError().code, "server_error")
    assertEquals(OAuth2Error.TemporarilyUnavailable().code, "temporarily_unavailable")
  }

  test("every error carries the status the RFC assigns to it") {
    assertEquals(OAuth2Error.InvalidRequest().status, 400)
    assertEquals(OAuth2Error.InvalidClient().status, 401)
    assertEquals(OAuth2Error.InvalidGrant().status, 400)
    assertEquals(OAuth2Error.UnauthorizedClient().status, 400)
    assertEquals(OAuth2Error.UnsupportedGrantType().status, 400)
    assertEquals(OAuth2Error.InvalidScope().status, 400)
    assertEquals(OAuth2Error.AccessDenied().status, 403)
    assertEquals(OAuth2Error.UnsupportedResponseType().status, 400)
    assertEquals(OAuth2Error.ServerError().status, 500)
    assertEquals(OAuth2Error.TemporarilyUnavailable().status, 503)
  }

  test("the body is the code alone when nothing else is given") {
    assertEquals(OAuth2Error.InvalidGrant().body, Map("error" -> "invalid_grant"))
  }

  test("the body adds description and uri only when present") {
    val e = OAuth2Error.InvalidScope(Some("unknown scope"), Some("https://example.com/e"))
    assertEquals(
      e.body,
      Map(
        "error" -> "invalid_scope",
        "error_description" -> "unknown scope",
        "error_uri" -> "https://example.com/e"
      )
    )
  }

  test("only an authentication failure produces a challenge") {
    assertEquals(OAuth2Error.InvalidClient().challenge, Some("""Basic realm="oauth2""""))
    assertEquals(OAuth2Error.InvalidRequest().challenge, None)
    assertEquals(OAuth2Error.InvalidGrant().challenge, None)
    assertEquals(OAuth2Error.ServerError().challenge, None)
  }

  test("a parse failure becomes invalid_request") {
    val e = OAuth2Error.fromParseFailure(ParseFailure("ClientId", "empty"))
    assertEquals(e.code, "invalid_request")
    assertEquals(e.status, 400)
    assertEquals(e.description, Some("ClientId: empty"))
  }

  test("a wire body without a code is refused") {
    assert(OAuth2Error.fromWire(400, Map.empty).isLeft)
    assert(OAuth2Error.fromWire(400, Map("error_description" -> "gone")).isLeft)
  }

  test("an unknown wire code is refused") {
    assert(OAuth2Error.fromWire(400, Map("error" -> "invalid_thing")).isLeft)
  }

  test("a wire body whose status disagrees with its code is refused") {
    assert(OAuth2Error.fromWire(400, Map("error" -> "invalid_client")).isLeft)
    assert(OAuth2Error.fromWire(401, Map("error" -> "invalid_grant")).isLeft)
  }

  test("a wire body is parsed back into the error that wrote it") {
    val e = OAuth2Error.InvalidScope(Some("unknown scope"), Some("https://example.com/e"))
    assertEquals(OAuth2Error.fromWire(e.status, e.body), Right(e))
  }

  property("every error round trips through status and body") {
    forAll(genError) { e =>
      OAuth2Error.fromWire(e.status, e.body) == Right(e)
    }
  }

  property("code is one of the RFC 6749 codes") {
    forAll(genError) { e =>
      OAuth2Error.knownCodes.contains(e.code)
    }
  }

  property("status is one of the statuses the RFC assigns") {
    forAll(genError) { e =>
      OAuth2Error.knownStatuses.contains(e.status)
    }
  }

  property("the body always names the error and never more than three fields") {
    forAll(genError) { e =>
      e.body.get("error").contains(e.code) && e.body.size <= 3 &&
      e.body.keys.forall(k => ErrorSpec.bodyFields.contains(k))
    }
  }

  property("no error leaks a value that is not its own code, description or uri") {
    forAll(genError) { e =>
      e.body.forall {
        case ("error", v)                 => v == e.code
        case ("error_description", v)     => e.description.contains(v)
        case ("error_uri", v)             => e.errorUri.contains(v)
        case _                            => false
      }
    }
  }
}

object ErrorSpec {
  val bodyFields: Set[String] = Set("error", "error_description", "error_uri")
}
