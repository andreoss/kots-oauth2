package kots.oauth2.core

import cats.data.ValidatedNec
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class RequestsSpec extends ScalaCheckSuite {

  private val Unreserved: Vector[Char] =
    (('a' to 'z') ++ ('A' to 'Z') ++ ('0' to '9') ++ Seq('-', '.', '_', '~')).toVector

  private def textOf(n: Int): Gen[String] =
    Gen.listOfN(n, Gen.choose(0, Unreserved.length - 1).map(Unreserved)).map(_.mkString)

  private val genVerifier: Gen[CodeVerifier] =
    Gen.choose(43, 128).flatMap(textOf).map(CodeVerifier.from(_).toOption.get)

  private val genChallenge: Gen[CodeChallenge] =
    Gen.choose(43, 128).flatMap(textOf).map(CodeChallenge.from(_).toOption.get)

  private val genClientId: Gen[ClientId] =
    Gen.choose(1, 24).flatMap(n => textOf(n)).map(ClientId.from(_).toOption.get)

  private val genState: Gen[State] =
    Gen.choose(1, 24).flatMap(n => textOf(n)).map(State.from(_).toOption.get)

  private val Verifier: String = "abcdefghij" * 5
  private val Client: String = "client-1"
  private val Redirect: String = "https://example.com/cb"

  private def valid[A](decoded: ValidatedNec[OAuth2Error, A]): A =
    decoded.fold(errors => fail(errors.toChain.toList.map(_.code).mkString(",")), identity)

  private def errors[A](decoded: ValidatedNec[OAuth2Error, A]): List[OAuth2Error] =
    decoded.fold(_.toChain.toList, _ => Nil)

  private def authorization(extra: (String, String)*): ValidatedNec[OAuth2Error, AuthorizationRequest] =
    AuthorizationRequest.from(
      Map("response_type" -> "code", "client_id" -> Client, "state" -> "xyz") ++ extra
    )

  test("authorization request decodes the minimal code request") {
    val request = valid(authorization())
    assertEquals(request.responseType, ResponseType.Code)
    assertEquals(request.clientId.value, Client)
    assertEquals(request.redirectUri, None)
    assertEquals(request.scope, Scopes.empty)
    assertEquals(request.state.value, "xyz")
    assertEquals(request.pkce, None)
  }

  test("authorization request refuses a missing state") {
    val decoded = AuthorizationRequest.from(Map("response_type" -> "code", "client_id" -> Client))
    assertEquals(errors(decoded).map(_.code), List("invalid_request"))
  }

  test("authorization request decodes every field") {
    val request = valid(
      authorization(
        "redirect_uri" -> Redirect,
        "scope" -> "openid profile",
        "state" -> "xyz",
        "code_challenge" -> Verifier,
        "code_challenge_method" -> "S256"
      )
    )
    assertEquals(request.redirectUri.map(_.value), Some(Redirect))
    assertEquals(
      request.scope,
      Scopes.of(List(Scope.from("openid").toOption.get, Scope.from("profile").toOption.get))
    )
    assertEquals(request.state.value, "xyz")
    assertEquals(request.pkce.map(_.method), Some(CodeChallengeMethod.S256))
    assertEquals(request.pkce.map(_.challenge.value), Some(Verifier))
  }

  test("authorization request accumulates every missing and invalid field") {
    val decoded = AuthorizationRequest.from(Map.empty[String, String])
    assertEquals(errors(decoded).map(_.code), List("invalid_request", "invalid_request", "invalid_request"))

    val mixed = AuthorizationRequest.from(
      Map("response_type" -> "token", "client_id" -> "", "scope" -> "openid  profile")
    )
    assertEquals(
      errors(mixed).map(_.code).sorted,
      List("invalid_request", "invalid_request", "invalid_request", "unsupported_response_type")
    )
  }

  test("authorization request refuses an unsupported response type") {
    val decoded =
      AuthorizationRequest.from(Map("response_type" -> "id_token", "client_id" -> Client, "state" -> "xyz"))
    assertEquals(errors(decoded).map(_.code), List("unsupported_response_type"))
  }

  test("authorization request refuses an invalid redirect uri and state") {
    assertEquals(
      errors(authorization("redirect_uri" -> "https://example.com/*")).map(_.code),
      List("invalid_request")
    )
    assertEquals(errors(authorization("state" -> " ")).map(_.code), List("invalid_request"))
  }

  test("authorization request refuses a malformed scope") {
    assertEquals(errors(authorization("scope" -> "openid profile ")).map(_.code), List("invalid_request"))
    assertEquals(errors(authorization("scope" -> "open\tid")).map(_.code), List("invalid_request"))
  }

  test("authorization request defaults the challenge method to plain") {
    assertEquals(
      valid(authorization("code_challenge" -> Verifier)).pkce.map(_.method),
      Some(CodeChallengeMethod.Plain)
    )
  }

  test("authorization request refuses a method without a challenge") {
    assertEquals(
      errors(authorization("code_challenge_method" -> "S256")).map(_.code),
      List("invalid_request")
    )
  }

  test("authorization request refuses a malformed challenge and method") {
    assertEquals(errors(authorization("code_challenge" -> "short")).map(_.code), List("invalid_request"))
    assertEquals(
      errors(authorization("code_challenge" -> Verifier, "code_challenge_method" -> "MD5")).map(_.code),
      List("invalid_request")
    )
  }

  test("token request decodes an authorization code grant") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "authorization_code",
        "code" -> "code-1",
        "redirect_uri" -> Redirect,
        "code_verifier" -> Verifier,
        "client_id" -> Client
      )
    )
    val request = valid(decoded)
    request match {
      case TokenRequest.Code(code, redirectUri, verifier, clientId, resource) =>
        assertEquals(code.value, "code-1")
        assertEquals(redirectUri.map(_.value), Some(Redirect))
        assertEquals(verifier.value, Verifier)
        assertEquals(clientId.value, Client)
        assertEquals(resource, None)
      case other => fail(s"unexpected request $other")
    }
  }

  test("token request without a redirect uri decodes") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "authorization_code",
        "code" -> "code-1",
        "code_verifier" -> Verifier,
        "client_id" -> Client
      )
    )
    assertEquals(valid(decoded).asInstanceOf[TokenRequest.Code].redirectUri, None)
  }

  test("token request accumulates the missing code, verifier and client id") {
    val decoded = TokenRequest.from(Map("grant_type" -> "authorization_code"))
    assertEquals(errors(decoded).map(_.code), List("invalid_request", "invalid_request", "invalid_request"))
  }

  test("token request decodes a refresh token grant") {
    val decoded = TokenRequest.from(
      Map("grant_type" -> "refresh_token", "refresh_token" -> "rt-1", "client_id" -> Client)
    )
    valid(decoded) match {
      case TokenRequest.Refresh(refreshToken, scope, clientId, resource) =>
        assertEquals(refreshToken.value, "rt-1")
        assertEquals(scope, None)
        assertEquals(clientId.value, Client)
        assertEquals(resource, None)
      case other => fail(s"unexpected request $other")
    }
  }

  test("every minting grant decodes a resource indicator") {
    val bound = "https://api.example"
    val code = valid(
      TokenRequest.from(
        Map(
          "grant_type" -> "authorization_code",
          "code" -> "code-1",
          "code_verifier" -> Verifier,
          "client_id" -> Client,
          "resource" -> bound
        )
      )
    ).asInstanceOf[TokenRequest.Code]
    val refresh = valid(
      TokenRequest.from(
        Map(
          "grant_type" -> "refresh_token",
          "refresh_token" -> "rt-1",
          "client_id" -> Client,
          "resource" -> bound
        )
      )
    ).asInstanceOf[TokenRequest.Refresh]
    val credentials = valid(
      TokenRequest.from(Map("grant_type" -> "client_credentials", "client_id" -> Client, "resource" -> bound))
    ).asInstanceOf[TokenRequest.ClientCredentials]
    val device = valid(
      TokenRequest.from(
        Map(
          "grant_type" -> "urn:ietf:params:oauth:grant-type:device_code",
          "device_code" -> "device-1",
          "client_id" -> Client,
          "resource" -> bound
        )
      )
    ).asInstanceOf[TokenRequest.Device]
    assertEquals(code.resource.map(_.value), Some(bound))
    assertEquals(refresh.resource.map(_.value), Some(bound))
    assertEquals(credentials.resource.map(_.value), Some(bound))
    assertEquals(device.resource.map(_.value), Some(bound))
  }

  test("the authorization and device authorization requests decode a resource indicator") {
    val request = valid(
      authorization(
        "code_challenge" -> Verifier,
        "code_challenge_method" -> "S256",
        "resource" -> "https://api.example"
      )
    )
    assertEquals(request.resource.map(_.value), Some("https://api.example"))
    val device =
      valid(DeviceAuthorizationRequest.from(Map("client_id" -> Client, "resource" -> "https://api.example")))
    assertEquals(device.resource.map(_.value), Some("https://api.example"))
  }

  test("token request decodes a refresh token grant with a narrower scope") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "refresh_token",
        "refresh_token" -> "rt-1",
        "scope" -> "read",
        "client_id" -> Client
      )
    )
    val request = valid(decoded).asInstanceOf[TokenRequest.Refresh]
    assertEquals(request.scope, Some(Scopes.of(List(Scope.from("read").toOption.get))))
  }

  test("token request accumulates the missing refresh token and client id") {
    val decoded = TokenRequest.from(Map("grant_type" -> "refresh_token"))
    assertEquals(errors(decoded).map(_.code), List("invalid_request", "invalid_request"))
  }

  test("token request refuses a malformed refresh scope") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "refresh_token",
        "refresh_token" -> "rt-1",
        "scope" -> "read  write",
        "client_id" -> Client
      )
    )
    assertEquals(errors(decoded).map(_.code), List("invalid_request"))
  }

  test("token request decodes a client credentials grant") {
    val decoded = TokenRequest.from(Map("grant_type" -> "client_credentials", "client_id" -> Client))
    valid(decoded) match {
      case TokenRequest.ClientCredentials(scope, clientId, resource) =>
        assertEquals(scope, None)
        assertEquals(clientId.value, Client)
        assertEquals(resource, None)
      case other => fail(s"unexpected request $other")
    }
  }

  test("token request decodes a client credentials grant with a scope") {
    val decoded = TokenRequest.from(
      Map("grant_type" -> "client_credentials", "scope" -> "read write", "client_id" -> Client)
    )
    val request = valid(decoded).asInstanceOf[TokenRequest.ClientCredentials]
    assertEquals(request.scope.map(_.value.map(_.value)), Some(Set("read", "write")))
  }

  test("token request accumulates a missing client id and a malformed scope") {
    val decoded = TokenRequest.from(Map("grant_type" -> "client_credentials", "scope" -> "read  write"))
    assertEquals(errors(decoded).map(_.code), List("invalid_request", "invalid_request"))
  }

  test("token request decodes a device code grant") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "urn:ietf:params:oauth:grant-type:device_code",
        "device_code" -> "device-1",
        "client_id" -> Client
      )
    )
    val request = valid(decoded).asInstanceOf[TokenRequest.Device]
    assertEquals(request.deviceCode.value, "device-1")
    assertEquals(request.clientId.value, Client)
  }

  test("token request accumulates a missing device code and client id") {
    val decoded = TokenRequest.from(Map("grant_type" -> "urn:ietf:params:oauth:grant-type:device_code"))
    assertEquals(errors(decoded).map(_.code), List("invalid_request", "invalid_request"))
  }

  test("device authorization request decodes the scope and client id") {
    val decoded = DeviceAuthorizationRequest.from(Map("client_id" -> Client, "scope" -> "read write"))
    val request = valid(decoded)
    assertEquals(request.clientId.value, Client)
    assertEquals(request.scope.map(_.value.map(_.value)), Some(Set("read", "write")))
  }

  test("device authorization request refuses a missing client id") {
    assertEquals(
      errors(DeviceAuthorizationRequest.from(Map.empty[String, String])).map(_.code),
      List("invalid_request")
    )
  }

  test("token request decodes a token exchange with every parameter") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token" -> "at-1",
        "subject_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
        "actor_token" -> "at-2",
        "actor_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
        "audience" -> "https://api.example",
        "resource" -> "https://api.example/v1",
        "scope" -> "read",
        "client_id" -> Client
      )
    )
    val request = valid(decoded).asInstanceOf[TokenRequest.Exchange]
    assertEquals(request.subjectToken.value, "at-1")
    assertEquals(request.actorToken.map(_.value), Some("at-2"))
    assertEquals(request.audience.map(_.value), Some("https://api.example"))
    assertEquals(request.resource.map(_.value), Some("https://api.example/v1"))
    assertEquals(request.scope.map(_.value.map(_.value)), Some(Set("read")))
    assertEquals(request.clientId.value, Client)
  }

  test("token request decodes a token exchange without the optional parameters") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token" -> "at-1",
        "subject_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
        "client_id" -> Client
      )
    )
    val request = valid(decoded).asInstanceOf[TokenRequest.Exchange]
    assertEquals(request.actorToken, None)
    assertEquals(request.audience, None)
    assertEquals(request.resource, None)
    assertEquals(request.scope, None)
  }

  test("token exchange refuses an actor token and its type apart") {
    def decoded(extra: (String, String)) = TokenRequest.from(
      Map(
        "grant_type" -> "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token" -> "at-1",
        "subject_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
        "client_id" -> Client,
        extra._1 -> extra._2
      )
    )
    assertEquals(errors(decoded("actor_token" -> "at-2")).map(_.code), List("invalid_request"))
    assertEquals(
      errors(decoded("actor_token_type" -> "urn:ietf:params:oauth:token-type:access_token")).map(_.code),
      List("invalid_request")
    )
  }

  test("token exchange refuses a token type outside the allow-list") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token" -> "at-1",
        "subject_token_type" -> "urn:ietf:params:oauth:token-type:jwt",
        "client_id" -> Client
      )
    )
    assertEquals(errors(decoded).map(_.code), List("invalid_request"))
    assertEquals(
      ExchangeTokenType.from("urn:ietf:params:oauth:token-type:access_token"),
      Right(ExchangeTokenType.AccessToken)
    )
    assert(ExchangeTokenType.from("urn:ietf:params:oauth:token-type:refresh_token").isLeft)
  }

  test("token request refuses an unsupported grant type") {
    assertEquals(
      errors(TokenRequest.from(Map("grant_type" -> "password"))).map(_.code),
      List("unsupported_grant_type")
    )
    assertEquals(errors(TokenRequest.from(Map.empty[String, String])).map(_.code), List("invalid_request"))
  }

  test("token request refuses a malformed code verifier") {
    val decoded = TokenRequest.from(
      Map(
        "grant_type" -> "authorization_code",
        "code" -> "code-1",
        "code_verifier" -> "short",
        "client_id" -> Client
      )
    )
    assertEquals(errors(decoded).map(_.code), List("invalid_request"))
  }

  test("code verifier accepts 43 to 128 unreserved characters") {
    assert(CodeVerifier.from(Verifier).isRight)
    assert(CodeVerifier.from("a" * 43).isRight)
    assert(CodeVerifier.from("a" * 128).isRight)
    assert(CodeVerifier.from("a" * 42).isLeft)
    assert(CodeVerifier.from("a" * 129).isLeft)
    assert(CodeVerifier.from("a" * 42 + "+").isLeft)
  }

  test("code challenge accepts 43 to 128 base64url characters") {
    assert(CodeChallenge.from(Verifier).isRight)
    assert(CodeChallenge.from("a" * 42).isLeft)
    assert(CodeChallenge.from("a" * 42 + "=").isLeft)
    assert(CodeChallenge.from("a" * 42 + "/").isLeft)
  }

  test("challenge method parses the two registered values") {
    assertEquals(CodeChallengeMethod.from("S256").toOption, Some(CodeChallengeMethod.S256))
    assertEquals(CodeChallengeMethod.from("plain").toOption, Some(CodeChallengeMethod.Plain))
    assert(CodeChallengeMethod.from("s256").isLeft)
  }

  property("a decoded authorization request round trips its fields") {
    forAll(genClientId, genState, genChallenge) { (clientId, state, challenge) =>
      val params = Map(
        "response_type" -> "code",
        "client_id" -> clientId.value,
        "state" -> state.value,
        "code_challenge" -> challenge.value,
        "code_challenge_method" -> "S256",
        "redirect_uri" -> Redirect,
        "scope" -> "openid profile"
      )
      val request = AuthorizationRequest.from(params).toOption.get
      request.clientId == clientId &&
      request.state == state &&
      request.pkce.map(_.challenge).contains(challenge) &&
      request.pkce.map(_.method).contains(CodeChallengeMethod.S256) &&
      request.redirectUri.map(_.value).contains(Redirect) &&
      Scopes.contains(request.scope, Scope.from("openid").toOption.get)
    }
  }

  property("removing a required field invalidates an authorization request") {
    forAll(genClientId, genState) { (clientId, state) =>
      val complete = Map("response_type" -> "code", "client_id" -> clientId.value, "state" -> state.value)
      AuthorizationRequest.from(complete).isValid &&
      !AuthorizationRequest.from(complete - "response_type").isValid &&
      !AuthorizationRequest.from(complete - "client_id").isValid &&
      !AuthorizationRequest.from(complete - "state").isValid
    }
  }

  property("decoded challenges and verifiers keep their length bounds") {
    forAll(genVerifier, genChallenge) { (verifier, challenge) =>
      verifier.value.length >= 43 && verifier.value.length <= 128 &&
      challenge.value.length >= 43 && challenge.value.length <= 128
    }
  }
}
