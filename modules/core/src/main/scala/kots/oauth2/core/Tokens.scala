package kots.oauth2.core

final case class AuthorizationCode private (value: String)

object AuthorizationCode {
  def from(raw: String): Either[ParseFailure, AuthorizationCode] =
    Text.printable("AuthorizationCode", raw).map(new AuthorizationCode(_))
}

final case class AccessToken private (value: String)

object AccessToken {
  def from(raw: String): Either[ParseFailure, AccessToken] =
    Text.printableToken("AccessToken", raw).map(new AccessToken(_))
}

final case class RefreshToken private (value: String)

object RefreshToken {
  def from(raw: String): Either[ParseFailure, RefreshToken] =
    Text.printable("RefreshToken", raw).map(new RefreshToken(_))
}

final case class DeviceCode private (value: String)

object DeviceCode {
  def from(raw: String): Either[ParseFailure, DeviceCode] =
    Text.printable("DeviceCode", raw).map(new DeviceCode(_))
}

final case class UserCode private (value: String)

object UserCode {
  def from(raw: String): Either[ParseFailure, UserCode] =
    Text.printable("UserCode", raw).map(new UserCode(_))
}

final case class AccessTokenHash private (value: String)

object AccessTokenHash {

  def of(token: AccessToken): AccessTokenHash = new AccessTokenHash(Digests.sha256Hex(token.value))

  def fromStored(raw: String): Either[ParseFailure, AccessTokenHash] =
    Either.cond(
      TokenHashes.isSha256Hex(raw),
      new AccessTokenHash(raw),
      TokenHashes.malformed("AccessTokenHash")
    )

  def verify(hash: AccessTokenHash, token: AccessToken): Boolean =
    Digests.equal(hash.value, Digests.sha256Hex(token.value))
}

private[core] object TokenHashes {

  def isSha256Hex(raw: String): Boolean =
    raw.length == 64 && raw.forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))

  def malformed(typeName: String): ParseFailure = ParseFailure(typeName, "not a sha-256 hex")
}

final case class RefreshTokenHash private (value: String)

object RefreshTokenHash {

  def of(token: RefreshToken): RefreshTokenHash = new RefreshTokenHash(Digests.sha256Hex(token.value))

  def fromStored(raw: String): Either[ParseFailure, RefreshTokenHash] =
    Either.cond(
      TokenHashes.isSha256Hex(raw),
      new RefreshTokenHash(raw),
      TokenHashes.malformed("RefreshTokenHash")
    )

  def verify(hash: RefreshTokenHash, token: RefreshToken): Boolean =
    Digests.equal(hash.value, Digests.sha256Hex(token.value))
}
