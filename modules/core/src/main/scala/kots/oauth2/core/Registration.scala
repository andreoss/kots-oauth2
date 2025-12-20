package kots.oauth2.core

final case class ClientRegistration(
    redirectUris: Set[RedirectUri],
    authMethod: ClientAuthMethod,
    scopes: Scopes
)
