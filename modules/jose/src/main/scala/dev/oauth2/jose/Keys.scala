package dev.oauth2.jose

import dev.oauth2.core.KeyId
import dev.oauth2.core.ParseFailure

sealed trait Kty {
  def value: String
}

object Kty {

  case object Rsa extends Kty { val value: String = "RSA" }

  case object Ec extends Kty { val value: String = "EC" }

  case object Okp extends Kty { val value: String = "OKP" }

  val all: Set[Kty] = Set(Rsa, Ec, Okp)

  def from(raw: String): Either[ParseFailure, Kty] =
    all.find(_.value == raw).toRight(ParseFailure("Kty", "not allowed"))
}

sealed trait Use {
  def value: String
}

object Use {

  case object Sig extends Use { val value: String = "sig" }

  case object Enc extends Use { val value: String = "enc" }

  val all: Set[Use] = Set(Sig, Enc)

  def from(raw: String): Either[ParseFailure, Use] =
    all.find(_.value == raw).toRight(ParseFailure("Use", "not allowed"))
}

sealed trait Alg {
  def value: String

  def kty: Kty

  def use: Use
}

object Alg {

  case object RS256 extends Alg { val value: String = "RS256"; val kty: Kty = Kty.Rsa; val use: Use = Use.Sig }

  case object ES256 extends Alg { val value: String = "ES256"; val kty: Kty = Kty.Ec; val use: Use = Use.Sig }

  case object EdDSA extends Alg { val value: String = "EdDSA"; val kty: Kty = Kty.Okp; val use: Use = Use.Sig }

  val allowed: Set[Alg] = Set(RS256, ES256, EdDSA)

  def from(raw: String): Either[ParseFailure, Alg] =
    allowed.find(_.value == raw).toRight(ParseFailure("Alg", "not allowed"))
}

sealed trait Jwk {
  def kid: KeyId

  def alg: Alg

  def kty: Kty

  def use: Use = alg.use

  def parameters: Map[String, String]
}

final case class RsaKey private[jose] (kid: KeyId, alg: Alg, n: String, e: String) extends Jwk {
  val kty: Kty = Kty.Rsa

  val parameters: Map[String, String] = Map("n" -> n, "e" -> e)
}

final case class EcKey private[jose] (kid: KeyId, alg: Alg, crv: String, x: String, y: String) extends Jwk {
  val kty: Kty = Kty.Ec

  val parameters: Map[String, String] = Map("crv" -> crv, "x" -> x, "y" -> y)
}

final case class OkpKey private[jose] (kid: KeyId, alg: Alg, crv: String, x: String) extends Jwk {
  val kty: Kty = Kty.Okp

  val parameters: Map[String, String] = Map("crv" -> crv, "x" -> x)
}

object Jwk {

  def rsa(kid: KeyId, alg: Alg, n: String, e: String): Either[ParseFailure, Jwk] =
    for {
      _ <- matches(alg, Kty.Rsa)
      nValue <- Base64Url.parameter("n", n)
      eValue <- Base64Url.parameter("e", e)
    } yield new RsaKey(kid, alg, nValue, eValue)

  def ec(kid: KeyId, alg: Alg, crv: String, x: String, y: String): Either[ParseFailure, Jwk] =
    for {
      _ <- matches(alg, Kty.Ec)
      crvValue <- curve(alg, crv)
      xValue <- Base64Url.parameter("x", x)
      yValue <- Base64Url.parameter("y", y)
    } yield new EcKey(kid, alg, crvValue, xValue, yValue)

  def okp(kid: KeyId, alg: Alg, crv: String, x: String): Either[ParseFailure, Jwk] =
    for {
      _ <- matches(alg, Kty.Okp)
      crvValue <- curve(alg, crv)
      xValue <- Base64Url.parameter("x", x)
    } yield new OkpKey(kid, alg, crvValue, xValue)

  private def matches(alg: Alg, kty: Kty): Either[ParseFailure, Unit] =
    Either.cond(alg.kty == kty, (), ParseFailure("Jwk", "algorithm does not match the key type"))

  private def curve(alg: Alg, crv: String): Either[ParseFailure, String] =
    Either.cond(curveOf(alg).contains(crv), crv, ParseFailure("Jwk", "curve does not match the algorithm"))

  private def curveOf(alg: Alg): Option[String] =
    alg match {
      case Alg.ES256 => Some("P-256")
      case Alg.EdDSA => Some("Ed25519")
      case _         => None
    }
}
