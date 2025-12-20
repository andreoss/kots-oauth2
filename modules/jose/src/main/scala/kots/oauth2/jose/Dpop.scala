package kots.oauth2.jose

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.PrivateKey
import java.time.Instant
import java.util.Base64

import cats.syntax.traverse._

import kots.oauth2.core.JwtId
import kots.oauth2.core.KeyId
import kots.oauth2.core.KeyThumbprint
import kots.oauth2.core.ParseFailure
import io.circe.Json

object Dpop {

  val Type: String = "dpop+jwt"

  final case class Proof(
      thumbprint: KeyThumbprint,
      jti: JwtId,
      method: String,
      uri: String,
      issuedAt: Instant,
      nonce: Option[String]
  )

  def prove(
      alg: Alg,
      key: PrivateKey,
      jwk: Jwk,
      jti: JwtId,
      method: String,
      uri: String,
      issuedAt: Instant,
      nonce: Option[String] = None
  ): Either[ParseFailure, String] = {
    val header = Json.obj(
      "typ" -> Json.fromString(Type),
      "alg" -> Json.fromString(alg.value),
      "jwk" -> canonical(jwk)
    )
    val payload = Json
      .fromFields(
        List(
          "jti" -> Json.fromString(jti.value),
          "htm" -> Json.fromString(method),
          "htu" -> Json.fromString(uri),
          "iat" -> Json.fromLong(issuedAt.getEpochSecond)
        ) ++ nonce.map(value => "nonce" -> Json.fromString(value))
      )
      .noSpaces
    val input = encode(header.noSpaces.getBytes(StandardCharsets.UTF_8)) + "." +
      encode(payload.getBytes(StandardCharsets.UTF_8))
    Signatures
      .sign(alg, key, input.getBytes(StandardCharsets.US_ASCII))
      .map(signature => input + "." + encode(signature))
  }

  def verify(compact: String): Either[ParseFailure, Proof] =
    compact.split('.') match {
      case Array(header, payload, signature) =>
        for {
          fields <- parse(header)
          declared <- field(fields, "typ")
          _ <- Either.cond(declared == Type, (), ParseFailure("Dpop", s"not a $Type"))
          alg <- field(fields, "alg").flatMap(Alg.from)
          embedded <- fields.hcursor
            .get[Json]("jwk")
            .left
            .map(_ => ParseFailure("Dpop", "header has no jwk"))
          _ <- Either.cond(
            embedded.hcursor.get[String]("d").isLeft,
            (),
            ParseFailure("Dpop", "the jwk carries private members")
          )
          jkt <- thumbprintOf(embedded)
          jwk <- jwkOf(embedded, alg, jkt)
          publicKey <- PublicKeys.from(jwk)
          raw <- decode(signature)
          input = (header + "." + payload).getBytes(StandardCharsets.US_ASCII)
          _ <- Signatures.verify(alg, publicKey, input, raw)
          decoded <- decode(payload).map(bytes => new String(bytes, StandardCharsets.UTF_8))
          proof <- proofOf(decoded, jkt)
        } yield proof
      case _ => Left(ParseFailure("Dpop", "not a compact jws"))
    }

  def thumbprint(jwk: Jwk): Either[ParseFailure, KeyThumbprint] =
    KeyThumbprint.from(digest(canonical(jwk).noSpaces))

  private def canonical(jwk: Jwk): Json =
    Json.fromFields(
      (jwk.parameters + ("kty" -> jwk.kty.value)).toList.sortBy(_._1).map { case (name, value) =>
        name -> Json.fromString(value)
      }
    )

  private def thumbprintOf(embedded: Json): Either[ParseFailure, KeyThumbprint] =
    for {
      kty <- embedded.hcursor.get[String]("kty").left.map(_ => ParseFailure("Dpop", "jwk has no kty"))
      names <- members(kty)
      values <- names.traverse(name =>
        embedded.hcursor.get[String](name).left.map(_ => ParseFailure("Dpop", s"jwk has no $name"))
      )
      canonicalJson = Json.fromFields(
        (names.zip(values) :+ ("kty" -> kty)).sortBy(_._1).map { case (name, value) =>
          name -> Json.fromString(value)
        }
      )
      jkt <- KeyThumbprint.from(digest(canonicalJson.noSpaces))
    } yield jkt

  private def members(kty: String): Either[ParseFailure, List[String]] =
    kty match {
      case "RSA" => Right(List("e", "n"))
      case "EC"  => Right(List("crv", "x", "y"))
      case "OKP" => Right(List("crv", "x"))
      case _     => Left(ParseFailure("Dpop", "jwk key type is not allowed"))
    }

  private def jwkOf(embedded: Json, alg: Alg, jkt: KeyThumbprint): Either[ParseFailure, Jwk] = {
    val cursor = embedded.hcursor
    def parameter(name: String): Either[ParseFailure, String] =
      cursor.get[String](name).left.map(_ => ParseFailure("Dpop", s"jwk has no $name"))
    KeyId.from(jkt.value).flatMap { kid =>
      alg.kty match {
        case Kty.Rsa =>
          for {
            n <- parameter("n")
            e <- parameter("e")
            jwk <- Jwk.rsa(kid, alg, n, e)
          } yield jwk
        case Kty.Ec =>
          for {
            crv <- parameter("crv")
            x <- parameter("x")
            y <- parameter("y")
            jwk <- Jwk.ec(kid, alg, crv, x, y)
          } yield jwk
        case Kty.Okp =>
          for {
            crv <- parameter("crv")
            x <- parameter("x")
            jwk <- Jwk.okp(kid, alg, crv, x)
          } yield jwk
      }
    }
  }

  private def proofOf(payload: String, jkt: KeyThumbprint): Either[ParseFailure, Proof] =
    for {
      json <- io.circe.parser.parse(payload).left.map(_ => ParseFailure("Dpop", "payload is not json"))
      cursor = json.hcursor
      jti <- cursor
        .get[String]("jti")
        .left
        .map(_ => ParseFailure("Dpop", "no jti claim"))
        .flatMap(JwtId.from)
      htm <- cursor.get[String]("htm").left.map(_ => ParseFailure("Dpop", "no htm claim"))
      htu <- cursor.get[String]("htu").left.map(_ => ParseFailure("Dpop", "no htu claim"))
      iat <- cursor.get[Long]("iat").left.map(_ => ParseFailure("Dpop", "no iat claim"))
      nonce = cursor.get[String]("nonce").toOption
    } yield Proof(jkt, jti, htm, htu, Instant.ofEpochSecond(iat), nonce)

  private def digest(canonicalJson: String): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(
      MessageDigest.getInstance("SHA-256").digest(canonicalJson.getBytes(StandardCharsets.UTF_8))
    )

  private def parse(header: String): Either[ParseFailure, Json] =
    decode(header).flatMap(bytes =>
      io.circe.parser
        .parse(new String(bytes, StandardCharsets.UTF_8))
        .left
        .map(_ => ParseFailure("Dpop", "header is not json"))
    )

  private def field(header: Json, name: String): Either[ParseFailure, String] =
    header.hcursor.get[String](name).left.map(_ => ParseFailure("Dpop", s"header has no $name"))

  private def encode(raw: Array[Byte]): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(raw)

  private def decode(raw: String): Either[ParseFailure, Array[Byte]] =
    try Right(Base64.getUrlDecoder.decode(raw))
    catch { case _: IllegalArgumentException => Left(ParseFailure("Dpop", "not base64url")) }
}
