package kots.oauth2.core

final case class ProtectedResourceMetadata(
    resource: ResourceIndicator,
    authorizationServers: List[Issuer],
    scopesSupported: Scopes
)

final case class AuthorizationServerMetadata(
    issuer: Issuer,
    authorizationEndpoint: EndpointUri,
    tokenEndpoint: EndpointUri,
    revocationEndpoint: Option[EndpointUri],
    introspectionEndpoint: Option[EndpointUri],
    jwksUri: Option[EndpointUri],
    responseTypesSupported: Set[ResponseType],
    grantTypesSupported: Set[GrantType],
    tokenEndpointAuthMethodsSupported: Set[ClientAuthMethod],
    codeChallengeMethodsSupported: Set[CodeChallengeMethod],
    scopesSupported: Scopes
)

object AuthorizationServerMetadata {

  def of(
      issuer: Issuer,
      authorizationEndpoint: EndpointUri,
      tokenEndpoint: EndpointUri,
      revocationEndpoint: Option[EndpointUri],
      introspectionEndpoint: Option[EndpointUri],
      jwksUri: Option[EndpointUri],
      scopesSupported: Scopes
  ): AuthorizationServerMetadata =
    AuthorizationServerMetadata(
      issuer,
      authorizationEndpoint,
      tokenEndpoint,
      revocationEndpoint,
      introspectionEndpoint,
      jwksUri,
      ResponseType.all.toSet,
      GrantType.all.toSet,
      ClientAuthMethod.all.toSet,
      Set(CodeChallengeMethod.S256),
      scopesSupported
    )
}
