package dev.oauth2.store

import dev.oauth2.core.ClientId
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.Scopes

final case class Client(
    id: ClientId,
    redirectUris: Set[RedirectUri],
    scopes: Scopes,
    confidential: Boolean
) {
  def allowsRedirect(candidate: RedirectUri): Boolean =
    RedirectUri.matches(redirectUris, candidate)

  def allowsScopes(candidate: Scopes): Boolean =
    Scopes.isSubsetOf(candidate, scopes)
}

trait ClientStore[F[_]] {
  def find(id: ClientId): F[Option[Client]]
}
