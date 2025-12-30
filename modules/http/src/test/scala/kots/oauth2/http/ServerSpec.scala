package kots.oauth2.http

import cats.Id

import kots.oauth2.core.AccessToken
import kots.oauth2.core.IntrospectionResponse
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.Scopes
import munit.FunSuite
import sttp.monad.IdentityMonad
import sttp.tapir.server.ServerEndpoint

class ServerSpec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val accessToken: AccessToken = unsafe(AccessToken.from("at-1"))

  private val refreshToken: RefreshToken = unsafe(RefreshToken.from("rt-1"))

  private val scopes: Scopes = unsafe(Scopes.parse("openid read"))

  private def success(response: TokenResponse): TokenLogic[Id] =
    new TokenLogic[Id] {
      def apply(
          basic: Option[String],
          parameters: Map[String, String],
          proof: Option[String],
          certificate: Option[String]
      ) =
        Right(response)
    }

  private def failure(error: OAuth2Error): TokenLogic[Id] =
    new TokenLogic[Id] {
      def apply(
          basic: Option[String],
          parameters: Map[String, String],
          proof: Option[String],
          certificate: Option[String]
      ) =
        Left(error)
    }

  private type Bound[F[_]] = ServerEndpoint[Any, F] {
    type SECURITY_INPUT = Unit
    type PRINCIPAL = Unit
    type INPUT = (Option[String], Map[String, String])
    type ERROR_OUTPUT = OAuth2Error
    type OUTPUT = Map[String, String]
  }

  private type BoundToken[F[_]] = ServerEndpoint[Any, F] {
    type SECURITY_INPUT = Unit
    type PRINCIPAL = Unit
    type INPUT = (Option[String], Map[String, String], Option[String], Option[String])
    type ERROR_OUTPUT = OAuth2Error
    type OUTPUT = Map[String, String]
  }

  private def run(
      logic: TokenLogic[Id],
      input: (Option[String], Map[String, String], Option[String], Option[String])
  ) =
    Server.token(logic).asInstanceOf[BoundToken[Id]].logic(IdentityMonad)(())(input)

  test("a token response renders its type, lifetime, scope and refresh token") {
    val rendered = TokenResponse.render(TokenResponse(accessToken, 3600L, scopes, Some(refreshToken)))
    assertEquals(rendered("access_token"), "at-1")
    assertEquals(rendered("token_type"), "Bearer")
    assertEquals(rendered("expires_in"), "3600")
    assertEquals(rendered("scope"), "openid read")
    assertEquals(rendered("refresh_token"), "rt-1")
  }

  test("a token response without a scope or a refresh token renders neither") {
    val rendered = TokenResponse.render(TokenResponse(accessToken, 60L, Scopes.empty, None))
    assertEquals(rendered.keySet, Set("access_token", "token_type", "expires_in"))
  }

  test("a token response renders the issued token type when it carries one") {
    val rendered = TokenResponse.render(
      TokenResponse(
        accessToken,
        60L,
        Scopes.empty,
        None,
        Some(kots.oauth2.core.ExchangeTokenType.AccessToken)
      )
    )
    assertEquals(rendered("issued_token_type"), "urn:ietf:params:oauth:token-type:access_token")
    assertEquals(rendered("token_type"), "Bearer")
  }

  test("the bound logic answers through the described endpoint") {
    val endpoint = Server.token(success(TokenResponse(accessToken, 1L, Scopes.empty, None)))
    assertEquals(
      endpoint.showPathTemplate(showQueryParam = None),
      Endpoints.token.showPathTemplate(showQueryParam = None)
    )
    assertEquals(endpoint.method.map(_.method), Endpoints.token.method.map(_.method))
  }

  test("a answered token is rendered as the endpoint body") {
    val out =
      run(
        success(TokenResponse(accessToken, 3600L, scopes, None)),
        (None, Map("grant_type" -> "code"), None, None)
      )
    assertEquals(
      out,
      Right(
        Map(
          "access_token" -> "at-1",
          "token_type" -> "Bearer",
          "expires_in" -> "3600",
          "scope" -> "openid read"
        )
      )
    )
  }

  test("a refused token is carried through as the endpoint error") {
    val out = run(failure(OAuth2Error.InvalidGrant()), (None, Map.empty[String, String], None, None))
    assertEquals(out, Left(OAuth2Error.InvalidGrant()))
  }

  test("the token endpoint hands the dpop proof to the logic") {
    var seen: Option[String] = None
    val capturing = new TokenLogic[Id] {
      def apply(
          basic: Option[String],
          parameters: Map[String, String],
          proof: Option[String],
          certificate: Option[String]
      ) = {
        seen = proof
        Right(TokenResponse(accessToken, 1L, Scopes.empty, None))
      }
    }
    run(capturing, (None, Map("grant_type" -> "code"), Some("proof-1"), None))
    assertEquals(seen, Some("proof-1"))
  }

  test("the token endpoint hands the forwarded client certificate to the logic") {
    var seen: Option[String] = None
    val capturing = new TokenLogic[Id] {
      def apply(
          basic: Option[String],
          parameters: Map[String, String],
          proof: Option[String],
          certificate: Option[String]
      ) = {
        seen = certificate
        Right(TokenResponse(accessToken, 1L, Scopes.empty, None))
      }
    }
    run(capturing, (None, Map("grant_type" -> "code"), None, Some("pem")))
    assertEquals(seen, Some("pem"))
  }

  test("a dpop token response renders its own token type") {
    val rendered = TokenResponse.render(
      TokenResponse(accessToken, 60L, Scopes.empty, None, tokenType = "DPoP")
    )
    assertEquals(rendered("token_type"), "DPoP")
  }

  test("an introspection answer is rendered as the endpoint body") {
    val response = IntrospectionResponse.inactive
    val logic = new IntrospectionLogic[Id] {
      def apply(basic: Option[String], parameters: Map[String, String]) = Right(response)
    }
    val bound = Server.introspection(logic).asInstanceOf[Bound[Id]]
    assertEquals(bound.logic(IdentityMonad)(())((None, Map("token" -> "at-1"))), Right(response.body))
    assertEquals(
      bound.showPathTemplate(showQueryParam = None),
      Endpoints.introspection.showPathTemplate(showQueryParam = None)
    )
  }

  test("a metadata document is rendered with its endpoints and supported values") {
    val metadata = ServerSpec.document
    val rendered = Metadata.render(metadata)
    assertEquals(rendered(Metadata.Issuer), io.circe.Json.fromString("https://server.example"))
    assertEquals(rendered(Metadata.AuthorizationResponseIssParameterSupported), io.circe.Json.True)
    assertEquals(rendered(Metadata.TokenEndpoint), io.circe.Json.fromString("https://server.example/token"))
    assertEquals(
      rendered(Metadata.RevocationEndpoint),
      io.circe.Json.fromString("https://server.example/revocation")
    )
    assertEquals(
      rendered(Metadata.IntrospectionEndpoint),
      io.circe.Json.fromString("https://server.example/introspection")
    )
    assertEquals(rendered(Metadata.JwksUri), io.circe.Json.fromString("https://server.example/jwks"))
    assertEquals(rendered(Metadata.ScopesSupported), io.circe.Json.arr(io.circe.Json.fromString("read")))
    assertEquals(
      rendered(Metadata.CodeChallengeMethodsSupported),
      io.circe.Json.arr(io.circe.Json.fromString("S256"))
    )
    assertEquals(
      rendered(Metadata.GrantTypesSupported).asArray.get.map(_.asString.get).toSet,
      kots.oauth2.core.AuthorizationServerMetadata.DefaultGrantTypes.map(_.value)
    )
    assertEquals(
      rendered(Metadata.TokenEndpointAuthMethodsSupported).asArray.get.map(_.asString.get).toSet,
      kots.oauth2.core.ClientAuthMethod.all.map(_.value).toSet
    )
  }

  test("a metadata document without the optional endpoints renders neither") {
    val rendered = Metadata.render(
      ServerSpec.document.copy(revocationEndpoint = None, introspectionEndpoint = None, jwksUri = None)
    )
    assert(!rendered.contains(Metadata.RevocationEndpoint))
    assert(!rendered.contains(Metadata.IntrospectionEndpoint))
    assert(!rendered.contains(Metadata.JwksUri))
  }

  test("a device authorization response renders every field of the answer") {
    val response = DeviceAuthorizationResponse(
      unsafe(kots.oauth2.core.DeviceCode.from("device-1")),
      unsafe(kots.oauth2.core.UserCode.from("BCDF-GHJK")),
      unsafe(kots.oauth2.core.EndpointUri.from("https://server.example/device")),
      1800L,
      5L
    )
    val rendered = DeviceAuthorizationResponse.render(response)
    assertEquals(rendered("device_code"), "device-1")
    assertEquals(rendered("user_code"), "BCDF-GHJK")
    assertEquals(rendered("verification_uri"), "https://server.example/device")
    assertEquals(rendered("expires_in"), "1800")
    assertEquals(rendered("interval"), "5")
    assertEquals(
      rendered.keySet,
      Set("device_code", "user_code", "verification_uri", "expires_in", "interval")
    )
  }

  test("the bound device authorization logic answers with the rendered response") {
    val response = DeviceAuthorizationResponse(
      unsafe(kots.oauth2.core.DeviceCode.from("device-1")),
      unsafe(kots.oauth2.core.UserCode.from("BCDF-GHJK")),
      unsafe(kots.oauth2.core.EndpointUri.from("https://server.example/device")),
      1800L,
      5L
    )
    val logic = new DeviceAuthorizationLogic[Id] {
      def apply(basic: Option[String], parameters: Map[String, String]) = Right(response)
    }
    val bound = Server.deviceAuthorization(logic).asInstanceOf[Bound[Id]]
    assertEquals(
      bound.logic(IdentityMonad)(())((None, Map.empty[String, String])),
      Right(DeviceAuthorizationResponse.render(response))
    )
    assertEquals(
      bound.showPathTemplate(showQueryParam = None),
      Endpoints.deviceAuthorization.showPathTemplate(showQueryParam = None)
    )
  }

  test("the bound metadata logic answers with the rendered document") {
    val metadata = ServerSpec.document
    val bound = Server.metadata[cats.Id](metadata).asInstanceOf[ServerSpec.MetadataBound[cats.Id]]
    assertEquals(bound.logic(IdentityMonad)(())(()), Right(Metadata.render(metadata)))
  }

  test("a protected resource document is rendered with its resource, servers and scopes") {
    val rendered = Metadata.renderResource(ServerSpec.resource)
    assertEquals(rendered(Metadata.Resource), io.circe.Json.fromString("https://api.example"))
    assertEquals(
      rendered(Metadata.AuthorizationServers),
      io.circe.Json.arr(io.circe.Json.fromString("https://server.example"))
    )
    assertEquals(rendered(Metadata.ScopesSupported), io.circe.Json.arr(io.circe.Json.fromString("read")))
  }

  test("the bound protected resource logic answers with the rendered document") {
    val bound =
      Server.resourceMetadata[cats.Id](ServerSpec.resource).asInstanceOf[ServerSpec.MetadataBound[cats.Id]]
    assertEquals(bound.logic(IdentityMonad)(())(()), Right(Metadata.renderResource(ServerSpec.resource)))
    assertEquals(
      bound.showPathTemplate(showQueryParam = None),
      Endpoints.resourceMetadata.showPathTemplate(showQueryParam = None)
    )
  }

  test("the bound jwks logic answers with the rendered document") {
    val document = ServerSpec.keys
    val bound = Server.jwks[cats.Id](document).asInstanceOf[ServerSpec.MetadataBound[cats.Id]]
    assertEquals(bound.logic(IdentityMonad)(())(()), Right(JwkSet.render(document)))
    assertEquals(
      bound.showPathTemplate(showQueryParam = None),
      Endpoints.jwks.showPathTemplate(showQueryParam = None)
    )
  }

  test("a refused introspection is carried through as the endpoint error") {
    val logic = new IntrospectionLogic[Id] {
      def apply(basic: Option[String], parameters: Map[String, String]) = Left(OAuth2Error.InvalidClient())
    }
    val bound = Server.introspection(logic).asInstanceOf[Bound[Id]]
    assertEquals(
      bound.logic(IdentityMonad)(())((None, Map.empty[String, String])),
      Left(OAuth2Error.InvalidClient())
    )
  }
}

object ServerSpec {

  type MetadataBound[F[_]] = ServerEndpoint[Any, F] {
    type SECURITY_INPUT = Unit
    type PRINCIPAL = Unit
    type INPUT = Unit
    type ERROR_OUTPUT = OAuth2Error
    type OUTPUT = Map[String, io.circe.Json]
  }

  def keys: kots.oauth2.jose.Jwks =
    kots.oauth2.jose.Jwks(List(kots.oauth2.jose.Fakes.rsa("key-1")))

  def resource: kots.oauth2.core.ProtectedResourceMetadata = {
    def unsafe[A](parsed: Either[ParseFailure, A]): A =
      parsed.fold(_ => sys.error("fixture"), identity)
    kots.oauth2.core.ProtectedResourceMetadata(
      unsafe(kots.oauth2.core.ResourceIndicator.from("https://api.example")),
      List(unsafe(kots.oauth2.core.Issuer.from("https://server.example"))),
      unsafe(Scopes.parse("read"))
    )
  }

  def document: kots.oauth2.core.AuthorizationServerMetadata = {
    def unsafe[A](parsed: Either[ParseFailure, A]): A =
      parsed.fold(_ => sys.error("fixture"), identity)
    kots.oauth2.core.AuthorizationServerMetadata.of(
      unsafe(kots.oauth2.core.Issuer.from("https://server.example")),
      unsafe(kots.oauth2.core.EndpointUri.from("https://server.example/authorize")),
      unsafe(kots.oauth2.core.EndpointUri.from("https://server.example/token")),
      Some(unsafe(kots.oauth2.core.EndpointUri.from("https://server.example/revocation"))),
      Some(unsafe(kots.oauth2.core.EndpointUri.from("https://server.example/introspection"))),
      Some(unsafe(kots.oauth2.core.EndpointUri.from("https://server.example/jwks"))),
      unsafe(Scopes.parse("read"))
    )
  }
}
