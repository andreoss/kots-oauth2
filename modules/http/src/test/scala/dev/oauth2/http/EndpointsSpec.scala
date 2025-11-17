package dev.oauth2.http

import java.nio.charset.StandardCharsets
import java.util.Base64

import dev.oauth2.core.ClientAuthInput
import dev.oauth2.core.OAuth2Error
import munit.FunSuite
import sttp.apispec.openapi.OpenAPI
import sttp.apispec.openapi.ResponsesCodeKey
import sttp.tapir.DecodeResult
import sttp.tapir.EndpointInput
import sttp.tapir.docs.openapi.OpenAPIDocsInterpreter

class EndpointsSpec extends FunSuite {

  private val document: OpenAPI =
    OpenAPIDocsInterpreter().toOpenAPI(List(Endpoints.token), "OAuth 2.0", "1.0")

  private def tokenOperation =
    document.paths.pathItems("/token").post.getOrElse(fail("no token operation in the document"))

  private def accepted[A](result: DecodeResult[A]): Boolean =
    result match {
      case DecodeResult.Value(_) => true
      case _                     => false
    }

  private def refused[A](result: DecodeResult[A]): Boolean =
    result match {
      case _: DecodeResult.Failure => true
      case _                       => false
    }

  private def statusCodes: Set[Int] =
    tokenOperation.responses.responses.keys.collect { case ResponsesCodeKey(code) => code }.toSet

  test("the token endpoint is a form post at /token") {
    assertEquals(Endpoints.token.showPathTemplate(showQueryParam = None), "/token")
    assertEquals(Endpoints.token.method.map(_.method), Some("POST"))
    assertEquals(
      tokenOperation.requestBody.flatMap(_.toOption).map(_.content.keys.toList),
      Some(List("application/x-www-form-urlencoded"))
    )
  }

  test("the document names every status the error model can return") {
    assert(statusCodes.contains(200))
    assertEquals(Endpoints.statuses.map(_.code).toSet -- statusCodes, Set.empty[Int])
  }

  test("the described statuses are exactly those of the error model") {
    assertEquals(Endpoints.statuses.map(_.code).toSet, OAuth2Error.knownStatuses)
  }

  test("every described parameter is accepted by the form codec") {
    Endpoints.tokenParameters.foreach { name =>
      assert(accepted(Endpoints.formParameters.decode(s"$name=value")))
    }
  }

  test("the form codec decodes the parameters a token request carries") {
    val raw = "grant_type=authorization_code&code=abc&code_verifier=xyz"
    assertEquals(
      Endpoints.formParameters.decode(raw),
      DecodeResult.Value(Map("grant_type" -> "authorization_code", "code" -> "abc", "code_verifier" -> "xyz"))
    )
  }

  test("the form codec refuses a duplicated parameter") {
    assert(refused(Endpoints.formParameters.decode("grant_type=code&grant_type=code")))
  }

  test("the form codec refuses a parameter the token endpoint does not take") {
    assert(refused(Endpoints.formParameters.decode("grant_type=code&other=1")))
  }

  test("the form codec renders a body it can decode again") {
    val params = Map("code" -> "a b", "scope" -> "openid read")
    assertEquals(Endpoints.formParameters.decode(Endpoints.formParameters.encode(params)), DecodeResult.Value(params))
  }

  test("the token endpoint is described as requiring client credentials") {
    assert(tokenOperation.security.nonEmpty)
    assert(document.components.toList.flatMap(_.securitySchemes.toList).map(_._1).contains(Auth.BasicSchemeName))
  }

  test("the token endpoint takes an http basic auth input with the basic challenge") {
    assertEquals(Auth.basic.authType, EndpointInput.AuthType.Http("Basic"))
    assertEquals(Auth.basic.challenge.toString, OAuth2Error.BasicChallenge)
  }

  test("the basic input carries the value of a basic authorization header") {
    val encoded = Base64.getEncoder.encodeToString("client-1:s3cret".getBytes(StandardCharsets.UTF_8))
    assertEquals(Auth.basicValue.decode(List(encoded)), DecodeResult.Value(Some(encoded)))
  }

  test("the basic input carries no value without the header") {
    assertEquals(Auth.basicValue.decode(Nil), DecodeResult.Value(None))
  }

  test("the basic input carries the value it has written") {
    val encoded = Base64.getEncoder.encodeToString("client-1:s3cr%3At".getBytes(StandardCharsets.UTF_8))
    assertEquals(
      Auth.basicValue.decode(Auth.basicValue.encode(Some(encoded))),
      DecodeResult.Value(Some(encoded))
    )
  }

  test("a basic value is read by the core as credentials and refused when malformed") {
    val encoded = Base64.getEncoder.encodeToString("client-1:s3cr%3At".getBytes(StandardCharsets.UTF_8))
    assertEquals(
      ClientAuthInput.from(Some(encoded), Map.empty).toOption.flatMap(_.basic.map(_.secret.value)),
      Some("s3cr:t")
    )
    assert(ClientAuthInput.from(Some("not base64 !"), Map.empty).isInvalid)
  }

  test("the unauthorized error carries the challenge the error model knows") {
    val error = OAuth2Error.InvalidClient()
    assertEquals(
      Endpoints.challengedBody(sttp.model.StatusCode.Unauthorized).encode(error),
      (Some(OAuth2Error.BasicChallenge), error.body)
    )
  }

  test("an error of another status carries no challenge") {
    val error = OAuth2Error.InvalidGrant()
    assertEquals(Endpoints.challengedBody(sttp.model.StatusCode.BadRequest).encode(error), (None, error.body))
  }

  test("an error is written as the body the RFC assigns to it") {
    val error = OAuth2Error.InvalidClient(Some("bad"))
    assertEquals(Endpoints.errorBody(sttp.model.StatusCode.Unauthorized).encode(error), error.body)
  }

  test("a written error is read back as the same error") {
    val error = OAuth2Error.InvalidGrant()
    val status = sttp.model.StatusCode(error.status)
    assertEquals(Endpoints.errorBody(status).decode(Endpoints.errorBody(status).encode(error)), DecodeResult.Value(error))
  }

  test("a body whose code belongs to another status is refused") {
    val status = sttp.model.StatusCode(400)
    assert(refused(Endpoints.errorBody(status).decode(Map("error" -> "invalid_client"))))
  }

  test("a body that is not an error is refused") {
    val status = sttp.model.StatusCode(400)
    assert(refused(Endpoints.errorBody(status).decode(Map("error" -> "nope"))))
    assert(refused(Endpoints.errorBody(status).decode(Map.empty)))
  }
}
