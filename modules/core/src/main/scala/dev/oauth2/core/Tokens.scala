package dev.oauth2.core

final case class AuthorizationCode private (value: String)

object AuthorizationCode {
  def from(raw: String): Either[ParseFailure, AuthorizationCode] =
    Text.printable("AuthorizationCode", raw).map(new AuthorizationCode(_))
}

final case class AccessToken private (value: String)

object AccessToken {
  def from(raw: String): Either[ParseFailure, AccessToken] =
    Text.printable("AccessToken", raw).map(new AccessToken(_))
}

final case class RefreshToken private (value: String)

object RefreshToken {
  def from(raw: String): Either[ParseFailure, RefreshToken] =
    Text.printable("RefreshToken", raw).map(new RefreshToken(_))
}
