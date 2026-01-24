package kots.oauth2.jose

import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.util.Base64

import kots.oauth2.core.KeyId
import kots.oauth2.core.ParseFailure
import io.circe.Json

object Jws {

  val Type: String = "JWT"

  def sign(
      alg: Alg,
      kid: KeyId,
      key: PrivateKey,
      payload: String,
      typ: String = Type
  ): Either[ParseFailure, String] = {
    val header = Json.obj(
      "typ" -> Json.fromString(typ),
      "alg" -> Json.fromString(alg.value),
      "kid" -> Json.fromString(kid.value)
    )
    val input = encode(header.noSpaces.getBytes(StandardCharsets.UTF_8)) + "." +
      encode(payload.getBytes(StandardCharsets.UTF_8))
    Signatures
      .sign(alg, key, input.getBytes(StandardCharsets.US_ASCII))
      .map(signature => input + "." + encode(signature))
  }

  def unverified(compact: String, name: String): Either[ParseFailure, String] =
    compact.split('.') match {
      case Array(_, payload, _) => parse(payload).flatMap(field(_, name))
      case _                    => Left(ParseFailure("Jws", "not a compact jws"))
    }

  def verify(compact: String, keys: Jwks, typ: String = Type): Either[ParseFailure, String] =
    compact.split('.') match {
      case Array(header, payload, signature) =>
        for {
          fields <- parse(header)
          declared <- field(fields, "typ")
          _ <- Either.cond(declared == typ, (), ParseFailure("Jws", s"not a $typ"))
          alg <- field(fields, "alg").flatMap(Alg.from)
          kid <- field(fields, "kid").flatMap(KeyId.from)
          jwk <- keys.find(kid).toRight(ParseFailure("Jws", "no key for the kid"))
          _ <- Either.cond(jwk.alg == alg, (), ParseFailure("Jws", "algorithm does not match the key"))
          publicKey <- PublicKeys.from(jwk)
          raw <- decode(signature)
          input = (header + "." + payload).getBytes(StandardCharsets.US_ASCII)
          _ <- Signatures.verify(alg, publicKey, input, raw)
          decoded <- decode(payload).map(bytes => new String(bytes, StandardCharsets.UTF_8))
        } yield decoded
      case _ => Left(ParseFailure("Jws", "not a compact jws"))
    }

  private def parse(header: String): Either[ParseFailure, Json] =
    decode(header).flatMap(bytes =>
      io.circe.parser
        .parse(new String(bytes, StandardCharsets.UTF_8))
        .left
        .map(_ => ParseFailure("Jws", "header is not json"))
    )

  private def field(header: Json, name: String): Either[ParseFailure, String] =
    header.hcursor.get[String](name).left.map(_ => ParseFailure("Jws", s"header has no $name"))

  private def encode(raw: Array[Byte]): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(raw)

  private def decode(raw: String): Either[ParseFailure, Array[Byte]] =
    try Right(Base64.getUrlDecoder.decode(raw))
    catch { case _: IllegalArgumentException => Left(ParseFailure("Jws", "not base64url")) }
}
