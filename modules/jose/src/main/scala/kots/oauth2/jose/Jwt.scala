package kots.oauth2.jose

import java.security.PrivateKey
import java.time.Instant

import kots.oauth2.core.Acr
import kots.oauth2.core.Audience
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
    jkt: Option[KeyThumbprint] = None
)

object Jwt {

  val AccessTokenType: String = "at+jwt"

  def issue(signing: SigningKey, claims: JwtClaims): Either[ParseFailure, String] =
    Jws.sign(signing.alg, signing.kid, signing.key, render(claims), AccessTokenType)

  def claims(compact: String, keys: Jwks, now: Instant): Either[ParseFailure, JwtClaims] =
    for {
      payload <- Jws.verify(compact, keys, AccessTokenType)
      parsed <- parse(payload)
      _ <- Either.cond(now.isBefore(parsed.expiresAt), (), ParseFailure("Jwt", "expired"))
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
          claims.audience.map(value => "aud" -> Json.fromString(value.value)) ++
          claims.acr.map(value => "acr" -> Json.fromString(value.value)) ++
          claims.jkt.map(value => "cnf" -> Json.obj("jkt" -> Json.fromString(value.value))) ++
          (if (claims.scopes.value.isEmpty) Nil
           else
             List("scope" -> Json.fromString(claims.scopes.value.map(_.value).toVector.sorted.mkString(" "))))
      )
      .noSpaces

  private def parse(payload: String): Either[ParseFailure, JwtClaims] =
    for {
      json <- io.circe.parser.parse(payload).left.map(_ => ParseFailure("Jwt", "payload is not json"))
      cursor = json.hcursor
      issuer <- string(cursor, "iss").flatMap(Issuer.from)
      subject <- string(cursor, "sub").flatMap(Subject.from)
      clientId <- string(cursor, "client_id").flatMap(ClientId.from)
      tokenId <- string(cursor, "jti").flatMap(JwtId.from)
      issuedAt <- number(cursor, "iat")
      expiresAt <- number(cursor, "exp")
      audience <- cursor
        .get[String]("aud")
        .toOption
        .fold(
          Right(None): Either[ParseFailure, Option[Audience]]
        )(raw => Audience.from(raw).map(Some(_)))
      scopes <- cursor
        .get[String]("scope")
        .toOption
        .fold(
          Right(Scopes.empty): Either[ParseFailure, Scopes]
        )(raw => Scopes.parse(raw))
      acr <- cursor
        .get[String]("acr")
        .toOption
        .fold(
          Right(None): Either[ParseFailure, Option[Acr]]
        )(raw => Acr.from(raw).map(Some(_)))
      jkt <- cursor
        .downField("cnf")
        .get[String]("jkt")
        .toOption
        .fold(
          Right(None): Either[ParseFailure, Option[KeyThumbprint]]
        )(raw => KeyThumbprint.from(raw).map(Some(_)))
    } yield JwtClaims(issuer, subject, audience, clientId, scopes, issuedAt, expiresAt, tokenId, acr, jkt)

  private def string(cursor: io.circe.HCursor, name: String): Either[ParseFailure, String] =
    cursor.get[String](name).left.map(_ => ParseFailure("Jwt", s"no $name claim"))

  private def number(cursor: io.circe.HCursor, name: String): Either[ParseFailure, Instant] =
    cursor.get[Long](name).left.map(_ => ParseFailure("Jwt", s"no $name claim")).map(Instant.ofEpochSecond)
}
