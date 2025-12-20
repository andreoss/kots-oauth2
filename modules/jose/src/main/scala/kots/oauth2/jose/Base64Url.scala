package kots.oauth2.jose

import kots.oauth2.core.ParseFailure

private[jose] object Base64Url {

  def parameter(name: String, raw: String): Either[ParseFailure, String] =
    if (raw.isEmpty) Left(ParseFailure("Jwk", s"$name is empty"))
    else if (!raw.forall(isCharacter)) Left(ParseFailure("Jwk", s"$name is not base64url"))
    else if (raw.length % 4 == 1) Left(ParseFailure("Jwk", s"$name is not decodable base64url"))
    else Right(raw)

  private def isCharacter(c: Char): Boolean =
    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}
