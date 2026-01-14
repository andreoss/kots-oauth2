package dev.oauth2.client

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.Clock
import dev.oauth2.core.Issuer
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Scopes
import dev.oauth2.jose.Jwks
import dev.oauth2.jose.Jwt
import dev.oauth2.jose.JwtClaims

final class BearerGuard[F[_]: Monad](
    keys: F[Either[ParseFailure, Jwks]],
    issuer: Issuer,
    clock: Clock[F]
) {

  def verify(
      authorization: Option[String],
      required: Scopes
  ): F[Either[BearerGuard.Challenge, JwtClaims]] =
    authorization.filter(_.startsWith(BearerGuard.Scheme)) match {
      case None =>
        Monad[F].pure(Left(BearerGuard.missing): Either[BearerGuard.Challenge, JwtClaims])
      case Some(header) =>
        val token = header.drop(BearerGuard.Scheme.length)
        keys.flatMap {
          case Left(_) =>
            Monad[F].pure(Left(BearerGuard.invalidToken): Either[BearerGuard.Challenge, JwtClaims])
          case Right(published) =>
            clock.instant.map { now =>
              Jwt.claims(token, published, now) match {
                case Left(_) => Left(BearerGuard.invalidToken)
                case Right(claims) if claims.issuer != issuer => Left(BearerGuard.invalidToken)
                case Right(claims) if !Scopes.isSubsetOf(required, claims.scopes) =>
                  Left(BearerGuard.insufficientScope)
                case Right(claims) => Right(claims)
              }
            }
        }
    }
}

object BearerGuard {

  val Scheme: String = "Bearer "

  val Realm: String = "oauth2"

  final case class Challenge(status: Int, header: String)

  val missing: Challenge = Challenge(401, s"""Bearer realm="$Realm"""")

  val invalidToken: Challenge = Challenge(401, s"""Bearer realm="$Realm", error="invalid_token"""")

  val insufficientScope: Challenge =
    Challenge(403, s"""Bearer realm="$Realm", error="insufficient_scope"""")
}
