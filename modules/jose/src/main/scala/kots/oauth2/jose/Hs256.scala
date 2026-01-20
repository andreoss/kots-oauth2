package kots.oauth2.jose

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ParseFailure

object Hs256 {

  val Name: String = "HS256"

  private val Algorithm: String = "HmacSHA256"

  def sign(secret: ClientSecret, payload: String): String = {
    val header = encode(s"""{"alg":"$Name","typ":"JWT"}""".getBytes(StandardCharsets.UTF_8))
    val body = encode(payload.getBytes(StandardCharsets.UTF_8))
    val signing = s"$header.$body"
    s"$signing.${encode(mac(secret, signing))}"
  }

  def verify(compact: String, secret: ClientSecret): Either[ParseFailure, String] =
    compact.split('.') match {
      case Array(header, payload, signature) =>
        for {
          decodedHeader <- decode(header)
          fields <- io.circe.parser
            .parse(new String(decodedHeader, StandardCharsets.UTF_8))
            .left
            .map(_ => ParseFailure("Hs256", "header is not json"))
          alg <- fields.hcursor.get[String]("alg").left.map(_ => ParseFailure("Hs256", "no alg"))
          _ <- Either.cond(alg == Name, (), ParseFailure("Hs256", "not an hmac header"))
          presented <- decode(signature)
          _ <- Either.cond(
            MessageDigest.isEqual(mac(secret, s"$header.$payload"), presented),
            (),
            ParseFailure("Hs256", "mac mismatch")
          )
          decodedPayload <- decode(payload)
        } yield new String(decodedPayload, StandardCharsets.UTF_8)
      case _ => Left(ParseFailure("Hs256", "not a compact jws"))
    }

  private def mac(secret: ClientSecret, signing: String): Array[Byte] = {
    val engine = Mac.getInstance(Algorithm)
    engine.init(new SecretKeySpec(secret.value.getBytes(StandardCharsets.UTF_8), Algorithm))
    engine.doFinal(signing.getBytes(StandardCharsets.UTF_8))
  }

  private def encode(raw: Array[Byte]): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(raw)

  private def decode(raw: String): Either[ParseFailure, Array[Byte]] =
    try Right(Base64.getUrlDecoder.decode(raw))
    catch { case _: IllegalArgumentException => Left(ParseFailure("Hs256", "not base64url")) }
}
