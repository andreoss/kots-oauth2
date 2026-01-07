package dev.oauth2.http

import dev.oauth2.core.AuthorizationServerMetadata
import io.circe.Json

object Metadata {

  val Issuer: String = "issuer"

  val AuthorizationEndpoint: String = "authorization_endpoint"

  val TokenEndpoint: String = "token_endpoint"

  val RevocationEndpoint: String = "revocation_endpoint"

  val IntrospectionEndpoint: String = "introspection_endpoint"

  val ResponseTypesSupported: String = "response_types_supported"

  val GrantTypesSupported: String = "grant_types_supported"

  val TokenEndpointAuthMethodsSupported: String = "token_endpoint_auth_methods_supported"

  val CodeChallengeMethodsSupported: String = "code_challenge_methods_supported"

  val ScopesSupported: String = "scopes_supported"

  def render(metadata: AuthorizationServerMetadata): Map[String, Json] =
    Map(
      Issuer -> Json.fromString(metadata.issuer.value),
      AuthorizationEndpoint -> Json.fromString(metadata.authorizationEndpoint.value),
      TokenEndpoint -> Json.fromString(metadata.tokenEndpoint.value),
      ResponseTypesSupported -> values(metadata.responseTypesSupported.map(_.value)),
      GrantTypesSupported -> values(metadata.grantTypesSupported.map(_.value)),
      TokenEndpointAuthMethodsSupported -> values(metadata.tokenEndpointAuthMethodsSupported.map(_.value)),
      CodeChallengeMethodsSupported -> values(metadata.codeChallengeMethodsSupported.map(_.value)),
      ScopesSupported -> values(metadata.scopesSupported.value.map(_.value))
    ) ++
      metadata.revocationEndpoint.map(uri => RevocationEndpoint -> Json.fromString(uri.value)) ++
      metadata.introspectionEndpoint.map(uri => IntrospectionEndpoint -> Json.fromString(uri.value))

  private def values(raw: Set[String]): Json =
    Json.arr(raw.toVector.sorted.map(Json.fromString): _*)
}
