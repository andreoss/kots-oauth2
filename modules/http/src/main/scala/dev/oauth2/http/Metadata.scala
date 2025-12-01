package dev.oauth2.http

import dev.oauth2.core.AuthorizationServerMetadata
import dev.oauth2.core.ProtectedResourceMetadata
import io.circe.Json

object Metadata {

  val Issuer: String = "issuer"

  val AuthorizationEndpoint: String = "authorization_endpoint"

  val TokenEndpoint: String = "token_endpoint"

  val RevocationEndpoint: String = "revocation_endpoint"

  val IntrospectionEndpoint: String = "introspection_endpoint"

  val JwksUri: String = "jwks_uri"

  val ResponseTypesSupported: String = "response_types_supported"

  val GrantTypesSupported: String = "grant_types_supported"

  val TokenEndpointAuthMethodsSupported: String = "token_endpoint_auth_methods_supported"

  val CodeChallengeMethodsSupported: String = "code_challenge_methods_supported"

  val ScopesSupported: String = "scopes_supported"

  val AuthorizationResponseIssParameterSupported: String = "authorization_response_iss_parameter_supported"

  val Resource: String = "resource"

  val AuthorizationServers: String = "authorization_servers"

  def render(metadata: AuthorizationServerMetadata): Map[String, Json] =
    Map(
      Issuer -> Json.fromString(metadata.issuer.value),
      AuthorizationResponseIssParameterSupported -> Json.True,
      AuthorizationEndpoint -> Json.fromString(metadata.authorizationEndpoint.value),
      TokenEndpoint -> Json.fromString(metadata.tokenEndpoint.value),
      ResponseTypesSupported -> values(metadata.responseTypesSupported.map(_.value)),
      GrantTypesSupported -> values(metadata.grantTypesSupported.map(_.value)),
      TokenEndpointAuthMethodsSupported -> values(metadata.tokenEndpointAuthMethodsSupported.map(_.value)),
      CodeChallengeMethodsSupported -> values(metadata.codeChallengeMethodsSupported.map(_.value)),
      ScopesSupported -> values(metadata.scopesSupported.value.map(_.value))
    ) ++
      metadata.revocationEndpoint.map(uri => RevocationEndpoint -> Json.fromString(uri.value)) ++
      metadata.introspectionEndpoint.map(uri => IntrospectionEndpoint -> Json.fromString(uri.value)) ++
      metadata.jwksUri.map(uri => JwksUri -> Json.fromString(uri.value))

  def renderResource(metadata: ProtectedResourceMetadata): Map[String, Json] =
    Map(
      Resource -> Json.fromString(metadata.resource.value),
      AuthorizationServers -> Json.arr(
        metadata.authorizationServers.map(issuer => Json.fromString(issuer.value)): _*
      ),
      ScopesSupported -> values(metadata.scopesSupported.value.map(_.value))
    )

  private def values(raw: Set[String]): Json =
    Json.arr(raw.toVector.sorted.map(Json.fromString): _*)
}
