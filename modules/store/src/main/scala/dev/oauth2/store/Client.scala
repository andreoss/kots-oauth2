package dev.oauth2.store

import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.RegistrationTokenHash
import dev.oauth2.core.Scopes
import dev.oauth2.jose.Jwks

final case class Client(
    id: ClientId,
    redirectUris: Set[RedirectUri],
    scopes: Scopes,
    authMethod: ClientAuthMethod,
    secretHash: Option[ClientSecretHash],
    keys: Jwks = Jwks.empty,
    registrationTokenHash: Option[RegistrationTokenHash] = None,
    secret: Option[ClientSecret] = None
) {
  def confidential: Boolean = authMethod != ClientAuthMethod.None

  def allowsRedirect(candidate: RedirectUri): Boolean =
    RedirectUri.matches(redirectUris, candidate)

  def allowsScopes(candidate: Scopes): Boolean =
    Scopes.isSubsetOf(candidate, scopes)
}

trait ClientStore[F[_]] {
  def find(id: ClientId): F[Option[Client]]

  def save(client: Client): F[Unit]

  def delete(id: ClientId): F[Unit]
}
