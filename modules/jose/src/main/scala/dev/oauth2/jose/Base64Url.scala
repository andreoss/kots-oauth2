package dev.oauth2.jose

import dev.oauth2.core.ParseFailure

private[jose] object Base64Url {

  def parameter(name: String, raw: String): Either[ParseFailure, String] =
    if (raw.isEmpty) Left(ParseFailure("Jwk", s"$name is empty"))
    else if (!raw.forall(isCharacter)) Left(ParseFailure("Jwk", s"$name is not base64url"))
    else Right(raw)

  private def isCharacter(c: Char): Boolean =
    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}
