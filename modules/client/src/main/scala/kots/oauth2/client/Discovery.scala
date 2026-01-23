package kots.oauth2.client

import java.time.Instant

import cats.effect.Concurrent
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.Clock
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.Issuer
import kots.oauth2.core.KeyId
import kots.oauth2.core.Lifetime
import kots.oauth2.core.ParseFailure
import kots.oauth2.jose.Alg
import kots.oauth2.jose.Jwk
import kots.oauth2.jose.Jwks
import io.circe.Json
import org.http4s.Request
import org.http4s.Uri
import org.http4s.client.Client

final case class DiscoveredMetadata(
    issuer: Issuer,
    authorizationEndpoint: EndpointUri,
    tokenEndpoint: EndpointUri,
    jwksUri: EndpointUri
)

final class Discovery[F[_]: Concurrent] private (
    transport: Client[F],
    issuer: Issuer,
    clock: Clock[F],
    ttl: Lifetime,
    documents: Ref[F, Option[(Instant, DiscoveredMetadata)]],
    published: Ref[F, Option[(Instant, Jwks)]]
) {

  def metadata: F[Either[ParseFailure, DiscoveredMetadata]] =
    cached(documents)(fetchMetadata)

  def keys: F[Either[ParseFailure, Jwks]] =
    cached(published)(fetchKeys)

  def key(kid: KeyId): F[Either[ParseFailure, Jwk]] =
    keys.flatMap {
      case Left(failure) => Concurrent[F].pure(Left(failure): Either[ParseFailure, Jwk])
      case Right(set)    =>
        set.find(kid) match {
          case Some(found) => Concurrent[F].pure(Right(found): Either[ParseFailure, Jwk])
          case None        =>
            published.set(None) >> keys.map(
              _.flatMap(_.find(kid).toRight(ParseFailure("Discovery", "no key for the kid")))
            )
        }
    }

  def refresh: F[Unit] =
    documents.set(None) >> published.set(None)

  private def cached[A](
      cache: Ref[F, Option[(Instant, A)]]
  )(fetch: F[Either[ParseFailure, A]]): F[Either[ParseFailure, A]] =
    clock.instant.flatMap { now =>
      cache.get.flatMap {
        case Some((fetchedAt, value)) if !Lifetime.isExpired(now, fetchedAt, ttl) =>
          Concurrent[F].pure(Right(value): Either[ParseFailure, A])
        case _ =>
          fetch.flatMap {
            case Right(value) => cache.set(Some((now, value))).as(Right(value): Either[ParseFailure, A])
            case left         => Concurrent[F].pure(left)
          }
      }
    }

  private def fetchMetadata: F[Either[ParseFailure, DiscoveredMetadata]] =
    body(s"${issuer.value}/.well-known/oauth-authorization-server")
      .map(_.flatMap(Discovery.metadataOf(issuer, _)))

  private def fetchKeys: F[Either[ParseFailure, Jwks]] =
    metadata.flatMap {
      case Left(failure)   => Concurrent[F].pure(Left(failure): Either[ParseFailure, Jwks])
      case Right(document) => body(document.jwksUri.value).map(_.flatMap(Discovery.keysOf))
    }

  private def body(location: String): F[Either[ParseFailure, String]] =
    transport.run(Request[F](uri = Uri.unsafeFromString(location))).use { response =>
      response.bodyText.compile.string.map(text =>
        if (response.status.isSuccess) Right(text)
        else Left(ParseFailure("Discovery", s"answered ${response.status.code}"))
      )
    }
}

object Discovery {

  def create[F[_]: Concurrent](
      transport: Client[F],
      issuer: Issuer,
      clock: Clock[F],
      ttl: Lifetime
  ): F[Discovery[F]] =
    for {
      documents <- Ref.of[F, Option[(Instant, DiscoveredMetadata)]](None)
      published <- Ref.of[F, Option[(Instant, Jwks)]](None)
    } yield new Discovery(transport, issuer, clock, ttl, documents, published)

  private def metadataOf(expected: Issuer, text: String): Either[ParseFailure, DiscoveredMetadata] =
    for {
      json <- parse(text)
      cursor = json.hcursor
      declared <- string(cursor, "issuer").flatMap(Issuer.from)
      _ <- Either.cond(declared == expected, (), ParseFailure("Discovery", "issuer does not match"))
      authorization <- string(cursor, "authorization_endpoint").flatMap(EndpointUri.from)
      token <- string(cursor, "token_endpoint").flatMap(EndpointUri.from)
      jwks <- string(cursor, "jwks_uri").flatMap(EndpointUri.from)
    } yield DiscoveredMetadata(declared, authorization, token, jwks)

  def keys(text: String): Either[ParseFailure, Jwks] =
    for {
      json <- parse(text)
      entries <- json.hcursor
        .downField("keys")
        .values
        .toRight(ParseFailure("Discovery", "no keys array"))
    } yield Jwks(entries.toList.flatMap(entry => keyOf(entry).toOption))

  private def keysOf(text: String): Either[ParseFailure, Jwks] = keys(text)

  private def keyOf(entry: Json): Either[ParseFailure, Jwk] = {
    val cursor = entry.hcursor
    for {
      kid <- string(cursor, "kid").flatMap(KeyId.from)
      alg <- string(cursor, "alg").flatMap(Alg.from)
      kty <- string(cursor, "kty")
      key <- kty match {
        case "RSA" =>
          for {
            n <- string(cursor, "n")
            e <- string(cursor, "e")
            built <- Jwk.rsa(kid, alg, n, e)
          } yield built
        case "EC" =>
          for {
            crv <- string(cursor, "crv")
            x <- string(cursor, "x")
            y <- string(cursor, "y")
            built <- Jwk.ec(kid, alg, crv, x, y)
          } yield built
        case "OKP" =>
          for {
            crv <- string(cursor, "crv")
            x <- string(cursor, "x")
            built <- Jwk.okp(kid, alg, crv, x)
          } yield built
        case other => Left(ParseFailure("Discovery", s"unknown key type $other"))
      }
    } yield key
  }

  private def parse(text: String): Either[ParseFailure, Json] =
    io.circe.parser.parse(text).left.map(_ => ParseFailure("Discovery", "not json"))

  private def string(cursor: io.circe.HCursor, name: String): Either[ParseFailure, String] =
    cursor.get[String](name).left.map(_ => ParseFailure("Discovery", s"no $name"))
}
