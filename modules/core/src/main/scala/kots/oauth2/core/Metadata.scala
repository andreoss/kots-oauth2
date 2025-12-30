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
    scopesSupported: Scopes,
    registrationEndpoint: Option[EndpointUri] = None,
    deviceAuthorizationEndpoint: Option[EndpointUri] = None,
    pushedAuthorizationRequestEndpoint: Option[EndpointUri] = None
)

object AuthorizationServerMetadata {

  val DefaultGrantTypes: Set[GrantType] = GrantType.all.toSet - GrantType.IdJag

  def of(
      issuer: Issuer,
      authorizationEndpoint: EndpointUri,
      tokenEndpoint: EndpointUri,
      revocationEndpoint: Option[EndpointUri],
      introspectionEndpoint: Option[EndpointUri],
      jwksUri: Option[EndpointUri],
      scopesSupported: Scopes,
      registrationEndpoint: Option[EndpointUri] = None,
      deviceAuthorizationEndpoint: Option[EndpointUri] = None,
      pushedAuthorizationRequestEndpoint: Option[EndpointUri] = None,
      grantTypesSupported: Set[GrantType] = DefaultGrantTypes
  ): AuthorizationServerMetadata =
    AuthorizationServerMetadata(
      issuer,
      authorizationEndpoint,
      tokenEndpoint,
      revocationEndpoint,
      introspectionEndpoint,
      jwksUri,
      ResponseType.all.toSet,
      grantTypesSupported,
      ClientAuthMethod.all.toSet,
      Set(CodeChallengeMethod.S256),
      scopesSupported,
      registrationEndpoint,
      deviceAuthorizationEndpoint,
      pushedAuthorizationRequestEndpoint
    )
}
