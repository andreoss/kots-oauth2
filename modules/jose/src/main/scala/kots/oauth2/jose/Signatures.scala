package kots.oauth2.jose

import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

import kots.oauth2.core.ParseFailure

private[jose] object Signatures {

  def sign(alg: Alg, key: PrivateKey, input: Array[Byte]): Either[ParseFailure, Array[Byte]] =
    attempt("signing refused") {
      val signature = Signature.getInstance(jca(alg))
      signature.initSign(key)
      signature.update(input)
      val signed = signature.sign()
      alg match {
        case Alg.ES256 => Der.toRaw(signed, Der.P256Bytes)
        case _         => signed
      }
    }

  def verify(
      alg: Alg,
      key: PublicKey,
      input: Array[Byte],
      signature: Array[Byte]
  ): Either[ParseFailure, Unit] =
    attempt("signature refused") {
      val verifier = Signature.getInstance(jca(alg))
      verifier.initVerify(key)
      verifier.update(input)
      val encoded = alg match {
        case Alg.ES256 => Der.fromRaw(signature, Der.P256Bytes)
        case _         => signature
      }
      verifier.verify(encoded)
    }.flatMap(accepted => Either.cond(accepted, (), ParseFailure("Jws", "signature refused")))

  private def jca(alg: Alg): String =
    alg match {
      case Alg.RS256 => "SHA256withRSA"
      case Alg.ES256 => "SHA256withECDSA"
      case Alg.EdDSA => "Ed25519"
    }

  private def attempt[A](reason: String)(work: => A): Either[ParseFailure, A] =
    try Right(work)
    catch {
      case _: java.security.GeneralSecurityException | _: IllegalArgumentException =>
        Left(ParseFailure("Jws", reason))
    }
}

private[jose] object Der {

  val P256Bytes: Int = 32

  def fromRaw(raw: Array[Byte], size: Int): Array[Byte] = {
    require(raw.length == size * 2, "raw signature length")
    val r = integer(new BigInteger(1, raw.take(size)))
    val s = integer(new BigInteger(1, raw.drop(size)))
    val body = r ++ s
    Array(0x30.toByte, body.length.toByte) ++ body
  }

  def toRaw(der: Array[Byte], size: Int): Array[Byte] = {
    require(der.length > 4 && der(0) == 0x30.toByte, "der sequence")
    val rLength = der(3).toInt
    val r = new BigInteger(der.slice(4, 4 + rLength))
    val sLength = der(5 + rLength).toInt
    val s = new BigInteger(der.slice(6 + rLength, 6 + rLength + sLength))
    fixed(r, size) ++ fixed(s, size)
  }

  private def integer(value: BigInteger): Array[Byte] = {
    val bytes = value.toByteArray
    Array(0x02.toByte, bytes.length.toByte) ++ bytes
  }

  private def fixed(value: BigInteger, size: Int): Array[Byte] = {
    val raw = value.toByteArray.dropWhile(_ == 0)
    Array.fill[Byte](size - raw.length)(0) ++ raw
  }
}
