package kots.oauth2.http

import java.time.Instant

import kots.oauth2.core.AccessToken
import kots.oauth2.core.ClientId
import kots.oauth2.core.DeviceCode
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.IntrospectionResponse
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.RequestUri
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.TokenTypeHint
import kots.oauth2.core.UserCode
import io.circe.Json
import munit.FunSuite

class DocumentTypesSpec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(failure => sys.error(failure.toString), identity)

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val numbers: Set[String] = Set("expires_in", "interval", "exp", "iat", "nbf")

  private val flags: Set[String] = Set("active")

  private def typed(document: Map[String, Json]): Unit =
    document.foreach { case (name, value) =>
      if (numbers.contains(name)) assert(value.isNumber, s"$name is not a number: $value")
      else if (flags.contains(name)) assert(value.isBoolean, s"$name is not a boolean: $value")
      else {
        assert(value.isString, s"$name is not a string: $value")
        assert(!value.asString.contains(""), s"$name is rendered empty")
      }
    }

  private val token: Map[String, Json] =
    TokenResponse.render(
      TokenResponse(
        unsafe(AccessToken.from("at-1")),
        3600L,
        unsafe(Scopes.parse("read")),
        Some(unsafe(RefreshToken.from("rt-1")))
      )
    )

  private val device: Map[String, Json] =
    DeviceAuthorizationResponse.render(
      DeviceAuthorizationResponse(
        unsafe(DeviceCode.from("device-1")),
        unsafe(UserCode.from("BCDF-GHJK")),
        unsafe(EndpointUri.from("https://server.example/device")),
        1800L,
        5L
      )
    )

  private val pushed: Map[String, Json] =
    PushedAuthorizationResponse.render(
      PushedAuthorizationResponse(unsafe(RequestUri.from("urn:ietf:params:oauth:request_uri:abc")), 60L)
    )

  private val introspected: Map[String, Json] =
    IntrospectionDocument.render(
      IntrospectionResponse.active(
        TokenTypeHint.AccessToken,
        unsafe(Scopes.parse("read")),
        unsafe(ClientId.from("client-1")),
        unsafe(Subject.from("user-1")),
        Start,
        Start.plusSeconds(3600L),
        Start
      )
    )

  test("every member of a credential document carries the type its specification defines") {
    typed(token)
    typed(device)
    typed(pushed)
    typed(introspected)
    typed(IntrospectionDocument.render(IntrospectionResponse.inactive))
  }

  test("the numeric and boolean members are present where they are required") {
    assertEquals(token("expires_in"), Json.fromLong(3600L))
    assertEquals(device("expires_in"), Json.fromLong(1800L))
    assertEquals(device("interval"), Json.fromLong(5L))
    assertEquals(pushed("expires_in"), Json.fromLong(60L))
    assertEquals(introspected("active"), Json.True)
    assertEquals(introspected("exp"), Json.fromLong(Start.plusSeconds(3600L).getEpochSecond))
    assertEquals(introspected("iat"), Json.fromLong(Start.getEpochSecond))
    assertEquals(introspected("nbf"), Json.fromLong(Start.getEpochSecond))
    assertEquals(IntrospectionDocument.render(IntrospectionResponse.inactive)("active"), Json.False)
  }

  test("a registration document carries no member with nothing to say") {
    val registered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(
        unsafe(ClientId.from("client-9")),
        Some(unsafe(kots.oauth2.core.ClientSecret.from("s3cret-9"))),
        kots.oauth2.core.ClientRegistration(
          Set(unsafe(kots.oauth2.core.RedirectUri.from("https://client.example/cb"))),
          kots.oauth2.core.ClientAuthMethod.ClientSecretBasic,
          Scopes.empty
        )
      )
    )
    assert(!registered.contains(Registration.Scope), registered.toString)
    assertEquals(registered(Registration.SecretExpiresAt), Json.fromLong(0L))
    registered.foreach { case (name, value) =>
      assert(!value.asString.contains(""), s"$name is rendered empty")
    }
  }
}
