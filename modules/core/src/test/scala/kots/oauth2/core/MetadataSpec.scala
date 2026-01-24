package kots.oauth2.core

import munit.FunSuite

class MetadataSpec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val issuer: Issuer = unsafe(Issuer.from("https://server.example"))

  private val authorization: EndpointUri = unsafe(EndpointUri.from("https://server.example/authorize"))

  private val token: EndpointUri = unsafe(EndpointUri.from("https://server.example/token"))

  private val revocation: EndpointUri = unsafe(EndpointUri.from("https://server.example/revocation"))

  private val introspection: EndpointUri = unsafe(EndpointUri.from("https://server.example/introspection"))

  private val keys: EndpointUri = unsafe(EndpointUri.from("https://server.example/jwks"))

  private val metadata: AuthorizationServerMetadata =
    AuthorizationServerMetadata.of(
      issuer,
      authorization,
      token,
      Some(revocation),
      Some(introspection),
      Some(keys),
      unsafe(Scopes.parse("read write"))
    )

  test("an endpoint uri refuses a relative reference") {
    assert(EndpointUri.from("/token").isLeft)
  }

  test("an endpoint uri refuses a uri with a fragment") {
    assert(EndpointUri.from("https://server.example/token#x").isLeft)
  }

  test("an endpoint uri accepts an absolute https uri") {
    assertEquals(
      EndpointUri.from("https://server.example/token").map(_.value),
      Right("https://server.example/token")
    )
  }

  test("the metadata carries the issuer and every endpoint it serves") {
    assertEquals(metadata.issuer.value, "https://server.example")
    assertEquals(metadata.authorizationEndpoint, authorization)
    assertEquals(metadata.tokenEndpoint, token)
    assertEquals(metadata.revocationEndpoint, Some(revocation))
    assertEquals(metadata.introspectionEndpoint, Some(introspection))
    assertEquals(metadata.jwksUri, Some(keys))
  }

  test("the metadata offers only the code challenge method the server accepts") {
    assertEquals(metadata.codeChallengeMethodsSupported, Set[CodeChallengeMethod](CodeChallengeMethod.S256))
    assert(!metadata.codeChallengeMethodsSupported.contains(CodeChallengeMethod.Plain))
  }

  test("the metadata offers every registered response type, grant type and method") {
    assertEquals(metadata.responseTypesSupported, ResponseType.all.toSet)
    assertEquals(metadata.grantTypesSupported, AuthorizationServerMetadata.DefaultGrantTypes)
    assertEquals(metadata.tokenEndpointAuthMethodsSupported, ClientAuthMethod.all.toSet)
  }

  test("the metadata advertises the assertion grant only where it is configured") {
    assert(!metadata.grantTypesSupported.contains(GrantType.IdJag))
    val asserting = AuthorizationServerMetadata.of(
      issuer,
      authorization,
      token,
      None,
      None,
      None,
      Scopes.empty,
      grantTypesSupported = GrantType.all.toSet
    )
    assert(asserting.grantTypesSupported.contains(GrantType.IdJag))
  }

  test("the metadata carries the scopes the server supports") {
    assertEquals(metadata.scopesSupported.value.map(_.value), Set("read", "write"))
  }

  test("the metadata is built without the optional endpoints as well") {
    val minimal =
      AuthorizationServerMetadata.of(issuer, authorization, token, None, None, None, Scopes.empty)
    assertEquals(minimal.revocationEndpoint, None)
    assertEquals(minimal.introspectionEndpoint, None)
    assertEquals(minimal.jwksUri, None)
    assertEquals(minimal.registrationEndpoint, None)
    assertEquals(minimal.deviceAuthorizationEndpoint, None)
    assertEquals(minimal.pushedAuthorizationRequestEndpoint, None)
    assertEquals(minimal.scopesSupported, Scopes.empty)
  }

  test("the metadata advertises the registration, device and par endpoints it serves") {
    val registration = unsafe(EndpointUri.from("https://server.example/register"))
    val device = unsafe(EndpointUri.from("https://server.example/device_authorization"))
    val par = unsafe(EndpointUri.from("https://server.example/par"))
    val document = AuthorizationServerMetadata.of(
      issuer,
      authorization,
      token,
      None,
      None,
      None,
      Scopes.empty,
      registrationEndpoint = Some(registration),
      deviceAuthorizationEndpoint = Some(device),
      pushedAuthorizationRequestEndpoint = Some(par)
    )
    assertEquals(document.registrationEndpoint, Some(registration))
    assertEquals(document.deviceAuthorizationEndpoint, Some(device))
    assertEquals(document.pushedAuthorizationRequestEndpoint, Some(par))
  }

  test("the protected resource metadata carries the resource, its servers and scopes") {
    val resource = unsafe(ResourceIndicator.from("https://api.example"))
    val document = ProtectedResourceMetadata(resource, List(issuer), unsafe(Scopes.parse("read")))
    assertEquals(document.resource, resource)
    assertEquals(document.authorizationServers, List(issuer))
    assertEquals(document.scopesSupported.value.map(_.value), Set("read"))
  }
}
