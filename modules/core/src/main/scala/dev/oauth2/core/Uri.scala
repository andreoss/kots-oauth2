package dev.oauth2.core

final case class RedirectUri private (value: String)

object RedirectUri {
  def from(raw: String): Either[ParseFailure, RedirectUri] =
    Text.absolute("RedirectUri", raw).map(new RedirectUri(_))

  def exactMatch(registered: Set[RedirectUri], candidate: RedirectUri): Boolean =
    registered.contains(candidate)
}

final case class ResourceIndicator private (value: String)

object ResourceIndicator {
  def from(raw: String): Either[ParseFailure, ResourceIndicator] =
    Text.absolute("ResourceIndicator", raw).map(new ResourceIndicator(_))
}
