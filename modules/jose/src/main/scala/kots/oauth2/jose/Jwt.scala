package kots.oauth2.jose

import java.security.PrivateKey
import java.time.Instant

import cats.syntax.traverse._

import kots.oauth2.core.Acr
import kots.oauth2.core.Audience
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientId
import kots.oauth2.core.Issuer
import kots.oauth2.core.JwtId
import kots.oauth2.core.KeyId
import kots.oauth2.core.KeyThumbprint
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import io.circe.Json

final case class SigningKey(kid: KeyId, alg: Alg, key: PrivateKey)

final case class JwtClaims(
    issuer: Issuer,
    subject: Subject,
    audience: Option[Audience],
    clientId: ClientId,
    scopes: Scopes,
    issuedAt: Instant,
    expiresAt: Instant,
    tokenId: JwtId,
    acr: Option[Acr] = None,
    jkt: Option[KeyThumbprint] = None,
    x5t: Option[CertificateThumbprint] = None,
    notBefore: Option[Instant] = None
)

object Jwt {

  val AccessTokenType: String = "at+jwt"

  val IdentityAssertionTyp: String = "oauth-id-jag+jwt"

  def issue(signing: SigningKey, claims: JwtClaims): Either[ParseFailure, String] =
    Jws.sign(signing.alg, signing.kid, signing.key, render(claims), AccessTokenType)

  def claims(
      compact: String,
      keys: Jwks,
      now: Instant,
      types: Set[String] = Set(AccessTokenType),
      skew: java.time.Duration = java.time.Duration.ZERO
  ): Either[ParseFailure, JwtClaims] =
    for {
      payload <- types.toList
        .map(typ => Jws.verify(compact, keys, typ))
        .reduceLeft((first, second) => first.orElse(second))
      parsed <- parse(payload)
      _ <- Either.cond(now.minus(skew).isBefore(parsed.expiresAt), (), ParseFailure("Jwt", "expired"))
      _ <- Either.cond(
        !now.plus(skew).isBefore(parsed.issuedAt),
        (),
        ParseFailure("Jwt", "issued in the future")
      )
      _ <- parsed.notBefore match {
        case None        => Right(())
        case Some(valid) =>
          Either.cond(!now.plus(skew).isBefore(valid), (), ParseFailure("Jwt", "not yet valid"))
      }
    } yield parsed

  def render(claims: JwtClaims): String =
    Json
      .fromFields(
        List(
          "iss" -> Json.fromString(claims.issuer.value),
          "sub" -> Json.fromString(claims.subject.value),
          "client_id" -> Json.fromString(claims.clientId.value),
          "jti" -> Json.fromString(claims.tokenId.value),
          "iat" -> Json.fromLong(claims.issuedAt.getEpochSecond),
          "exp" -> Json.fromLong(claims.expiresAt.getEpochSecond)
        ) ++
          claims.notBefore.map(value => "nbf" -> Json.fromLong(value.getEpochSecond)) ++
          claims.audience.map(value => "aud" -> Json.fromString(value.value)) ++
          claims.acr.map(value => "acr" -> Json.fromString(value.value)) ++
          confirmation(claims) ++
          (if (claims.scopes.value.isEmpty) Nil
           else
             List("scope" -> Json.fromString(claims.scopes.value.map(_.value).toVector.sorted.mkString(" "))))
      )
      .noSpaces

  val CertificateConfirmation: String = "x5t#S256"

  private def confirmation(claims: JwtClaims): Option[(String, Json)] = {
    val members = claims.jkt.map(value => "jkt" -> Json.fromString(value.value)).toList ++
      claims.x5t.map(value => CertificateConfirmation -> Json.fromString(value.value)).toList
    if (members.isEmpty) None else Some("cnf" -> Json.fromFields(members))
  }

  private def parse(payload: String): Either[ParseFailure, JwtClaims] =
    for {
      json <- io.circe.parser.parse(payload).left.map(_ => ParseFailure("Jwt", "payload is not json"))
      cursor = json.hcursor
      issuer <- string(cursor, "iss").flatMap(Issuer.from)
      subject <- string(cursor, "sub").flatMap(Subject.from)
      clientId <- string(cursor, "client_id")
        .orElse(string(cursor, "azp"))
        .flatMap(ClientId.from)
      tokenId <- string(cursor, "jti").flatMap(JwtId.from)
      issuedAt <- number(cursor, "iat")
      expiresAt <- number(cursor, "exp")
      notBefore <- cursor
        .get[Long]("nbf")
        .toOption
        .traverse(seconds => (Right(Instant.ofEpochSecond(seconds)): Either[ParseFailure, Instant]))
      audience <- cursor.get[String]("aud").toOption.traverse(Audience.from)
      scopes <- cursor.get[String]("scope").toOption.traverse(Scopes.parse).map(_.getOrElse(Scopes.empty))
      acr <- cursor.get[String]("acr").toOption.traverse(Acr.from)
      jkt <- cursor.downField("cnf").get[String]("jkt").toOption.traverse(KeyThumbprint.from)
      x5t <- cursor
        .downField("cnf")
        .get[String](CertificateConfirmation)
        .toOption
        .traverse(CertificateThumbprint.from)
    } yield JwtClaims(
      issuer,
      subject,
      audience,
      clientId,
      scopes,
      issuedAt,
      expiresAt,
      tokenId,
      acr,
      jkt,
      x5t,
      notBefore
    )

  private def string(cursor: io.circe.HCursor, name: String): Either[ParseFailure, String] =
    cursor.get[String](name).left.map(_ => ParseFailure("Jwt", s"no $name claim"))

  private def number(cursor: io.circe.HCursor, name: String): Either[ParseFailure, Instant] =
    cursor.get[Long](name).left.map(_ => ParseFailure("Jwt", s"no $name claim")).map(Instant.ofEpochSecond)
}
