package dev.oauth2.core

import java.nio.charset.StandardCharsets

import cats.syntax.either._

final case class ClientSecret private (value: String)

object ClientSecret {
  def from(raw: String): Either[ParseFailure, ClientSecret] =
    Text.printable("ClientSecret", raw).map(new ClientSecret(_))
}

final case class ClientSecretHash private (value: String)

object ClientSecretHash {

  def of(secret: ClientSecret): ClientSecretHash = new ClientSecretHash(Digests.sha256Hex(secret.value))

  def verify(hash: ClientSecretHash, secret: ClientSecret): Boolean =
    Digests.equal(hash.value, Digests.sha256Hex(secret.value))
}

final case class ClientCredentials(id: ClientId, secret: ClientSecret)

object ClientCredentials {

  def fromBasic(header: String): Either[ParseFailure, ClientCredentials] =
    Either
      .catchNonFatal(java.util.Base64.getDecoder.decode(header.trim))
      .leftMap(_ => ParseFailure("ClientCredentials", "not base64"))
      .flatMap { raw =>
        val text = java.net.URLDecoder.decode(new String(raw, StandardCharsets.UTF_8), StandardCharsets.UTF_8)
        val colon = text.indexOf(':')
        if (colon < 0) Left(ParseFailure("ClientCredentials", "no separator"))
        else
          for {
            id <- ClientId.from(text.substring(0, colon))
            secret <- ClientSecret.from(text.substring(colon + 1))
          } yield ClientCredentials(id, secret)
      }
}

final case class RegistrationToken private (value: String)

object RegistrationToken {
  def from(raw: String): Either[ParseFailure, RegistrationToken] =
    Text.printable("RegistrationToken", raw).map(new RegistrationToken(_))
}

final case class RegistrationTokenHash private (value: String)

object RegistrationTokenHash {

  def of(token: RegistrationToken): RegistrationTokenHash =
    new RegistrationTokenHash(Digests.sha256Hex(token.value))

  def verify(hash: RegistrationTokenHash, token: RegistrationToken): Boolean =
    Digests.equal(hash.value, Digests.sha256Hex(token.value))
}
