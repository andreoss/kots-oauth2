package dev.oauth2.core

final case class CodeVerifier private (value: String)

object CodeVerifier {
  val MinLength: Int = 43
  val MaxLength: Int = 128

  def from(raw: String): Either[ParseFailure, CodeVerifier] =
    if (raw.length < MinLength || raw.length > MaxLength)
      Left(ParseFailure("CodeVerifier", s"not $MinLength to $MaxLength characters"))
    else if (!raw.forall(isUnreserved))
      Left(ParseFailure("CodeVerifier", "not an unreserved character"))
    else Right(new CodeVerifier(raw))

  private[core] def isUnreserved(c: Char): Boolean =
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
      c == '-' || c == '.' || c == '_' || c == '~'
}

final case class CodeChallenge private (value: String)

object CodeChallenge {
  val MinLength: Int = 43
  val MaxLength: Int = 128

  def from(raw: String): Either[ParseFailure, CodeChallenge] =
    if (raw.length < MinLength || raw.length > MaxLength)
      Left(ParseFailure("CodeChallenge", s"not $MinLength to $MaxLength characters"))
    else if (!raw.forall(CodeVerifier.isUnreserved))
      Left(ParseFailure("CodeChallenge", "not an unreserved character"))
    else Right(new CodeChallenge(raw))
}

sealed abstract class CodeChallengeMethod(val value: String)

object CodeChallengeMethod {
  case object S256 extends CodeChallengeMethod("S256")
  case object Plain extends CodeChallengeMethod("plain")

  val all: List[CodeChallengeMethod] = List(S256, Plain)

  def from(raw: String): Either[ParseFailure, CodeChallengeMethod] =
    all.find(_.value == raw).toRight(ParseFailure("CodeChallengeMethod", "not S256 or plain"))
}

final case class Pkce(challenge: CodeChallenge, method: CodeChallengeMethod)
