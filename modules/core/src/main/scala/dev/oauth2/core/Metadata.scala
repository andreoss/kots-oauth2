package dev.oauth2.core

final case class AuthorizationServerMetadata(
    issuer: Issuer,
    authorizationEndpoint: EndpointUri,
    tokenEndpoint: EndpointUri,
    revocationEndpoint: Option[EndpointUri],
    introspectionEndpoint: Option[EndpointUri],
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
      scopesSupported: Scopes
  ): AuthorizationServerMetadata =
    AuthorizationServerMetadata(
      issuer,
      authorizationEndpoint,
      tokenEndpoint,
      revocationEndpoint,
      introspectionEndpoint,
      ResponseType.all.toSet,
      GrantType.all.toSet,
      ClientAuthMethod.all.toSet,
      Set(CodeChallengeMethod.S256),
      scopesSupported
    )
}
