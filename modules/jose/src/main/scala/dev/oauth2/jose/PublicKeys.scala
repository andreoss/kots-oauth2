package dev.oauth2.jose

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.EdECPoint
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

import dev.oauth2.core.ParseFailure

private[jose] object PublicKeys {

  def from(jwk: Jwk): Either[ParseFailure, PublicKey] =
    jwk match {
      case key: RsaKey =>
        attempt {
          KeyFactory
            .getInstance("RSA")
            .generatePublic(new RSAPublicKeySpec(unsigned(key.n), unsigned(key.e)))
        }
      case key: EcKey =>
        attempt {
          val parameters = AlgorithmParameters.getInstance("EC")
          parameters.init(new ECGenParameterSpec("secp256r1"))
          val curve = parameters.getParameterSpec(classOf[ECParameterSpec])
          KeyFactory
            .getInstance("EC")
            .generatePublic(new ECPublicKeySpec(new ECPoint(unsigned(key.x), unsigned(key.y)), curve))
        }
      case key: OkpKey =>
        attempt {
          val raw = Base64.getUrlDecoder.decode(key.x)
          val xOdd = (raw(raw.length - 1) & 0x80) != 0
          val little = raw.clone()
          little(little.length - 1) = (little(little.length - 1) & 0x7f).toByte
          val y = new BigInteger(1, little.reverse)
          KeyFactory
            .getInstance("Ed25519")
            .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)))
        }
    }

  private def unsigned(parameter: String): BigInteger =
    new BigInteger(1, Base64.getUrlDecoder.decode(parameter))

  private def attempt(work: => PublicKey): Either[ParseFailure, PublicKey] =
    try Right(work)
    catch {
      case _: java.security.GeneralSecurityException | _: IllegalArgumentException =>
        Left(ParseFailure("Jws", "the published key cannot be read"))
    }
}
