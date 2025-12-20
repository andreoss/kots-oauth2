package kots.oauth2.client

import java.time.Instant

import cats.effect.IO
import kots.oauth2.core.Acr
import kots.oauth2.core.Audience
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.Issuer
import kots.oauth2.core.JwtId
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.jose.Fakes
import kots.oauth2.jose.Jwks
import kots.oauth2.jose.Jwt
import kots.oauth2.jose.JwtClaims
import munit.CatsEffectSuite

class BearerGuardSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val issuer: Issuer = unsafe(Issuer.from("https://server.example"))

  private val published: Jwks = Jwks(List(Fakes.signingJwk))

  private def clockAt(now: Instant): Clock[IO] =
    new Clock[IO] {
      def instant: IO[Instant] = IO.pure(now)
    }

  private def claims(
      scopes: String = "read write",
      issuedBy: Issuer = issuer,
      expiresAt: Instant = Start.plusSeconds(3600L)
  ): JwtClaims =
    JwtClaims(
      issuer = issuedBy,
      subject = unsafe(Subject.from("user-1")),
      audience = Some(unsafe(Audience.from("https://api.example"))),
      clientId = unsafe(ClientId.from("client-1")),
      scopes = unsafe(Scopes.parse(scopes)),
      issuedAt = Start,
      expiresAt = expiresAt,
      tokenId = unsafe(JwtId.from("jwt-1"))
    )

  private def bearer(minted: JwtClaims): Option[String] =
    Some("Bearer " + Jwt.issue(Fakes.signingKey, minted).toOption.get)

  private def guard(now: Instant = Start, audience: Option[Audience] = None): BearerGuard[IO] =
    new BearerGuard[IO](IO.pure(Right(published)), issuer, clockAt(now), audience)

  test("a valid bearer token is accepted with its claims") {
    guard()
      .verify(bearer(claims()), unsafe(Scopes.parse("read")))
      .map { verified =>
        assertEquals(verified.toOption.map(_.subject.value), Some("user-1"))
        assertEquals(verified.toOption.map(_.scopes), Some(unsafe(Scopes.parse("read write"))))
      }
  }

  test("a missing or non bearer header is challenged without an error code") {
    for {
      missing <- guard().verify(None, Scopes.empty)
      basic <- guard().verify(Some("Basic abc"), Scopes.empty)
    } yield {
      assertEquals(missing.left.toOption.map(_.status), Some(401))
      assert(missing.left.toOption.exists(!_.header.contains("error=")))
      assertEquals(basic.left.toOption.map(_.status), Some(401))
    }
  }

  test("a garbage, expired or foreign token is challenged as invalid_token") {
    for {
      garbage <- guard().verify(Some("Bearer not.a.jwt"), Scopes.empty)
      expired <- guard(Start.plusSeconds(3600L)).verify(bearer(claims()), Scopes.empty)
      foreign <- guard().verify(
        bearer(claims(issuedBy = unsafe(Issuer.from("https://other.example")))),
        Scopes.empty
      )
    } yield {
      assert(garbage.left.toOption.exists(_.header.contains("invalid_token")))
      assert(expired.left.toOption.exists(_.header.contains("invalid_token")))
      assert(foreign.left.toOption.exists(_.header.contains("invalid_token")))
      assertEquals(garbage.left.toOption.map(_.status), Some(401))
    }
  }

  test("a token without the required scope is challenged as insufficient_scope") {
    guard()
      .verify(bearer(claims(scopes = "read")), unsafe(Scopes.parse("write")))
      .map { refused =>
        assertEquals(refused.left.toOption.map(_.status), Some(403))
        assert(refused.left.toOption.exists(_.header.contains("insufficient_scope")))
      }
  }

  test("a token below the required acr is challenged for step up authentication") {
    val gold = unsafe(Acr.from("gold"))
    for {
      bare <- guard().verify(bearer(claims()), Scopes.empty, Some(gold))
      lesser <- guard().verify(
        bearer(claims().copy(acr = Some(unsafe(Acr.from("bronze"))))),
        Scopes.empty,
        Some(gold)
      )
    } yield {
      assertEquals(bare.left.toOption.map(_.status), Some(401))
      assert(bare.left.toOption.exists(_.header.contains("insufficient_user_authentication")))
      assert(bare.left.toOption.exists(_.header.contains("""acr_values="gold"""")))
      assert(lesser.left.toOption.exists(_.header.contains("insufficient_user_authentication")))
    }
  }

  test("a token carrying the required acr is accepted") {
    val gold = unsafe(Acr.from("gold"))
    guard()
      .verify(bearer(claims().copy(acr = Some(gold))), unsafe(Scopes.parse("read")), Some(gold))
      .map(verified => assertEquals(verified.toOption.flatMap(_.acr), Some(gold)))
  }

  test("a token for another audience is challenged as invalid_token") {
    guard(audience = Some(unsafe(Audience.from("https://other.example"))))
      .verify(bearer(claims()), Scopes.empty)
      .map { refused =>
        assertEquals(refused.left.toOption.map(_.status), Some(401))
        assert(refused.left.toOption.exists(_.header.contains("invalid_token")))
      }
  }

  test("a token without an audience is challenged when the guard demands one") {
    guard(audience = Some(unsafe(Audience.from("https://api.example"))))
      .verify(bearer(claims().copy(audience = None)), Scopes.empty)
      .map(refused => assert(refused.left.toOption.exists(_.header.contains("invalid_token"))))
  }

  test("a token carrying the demanded audience is accepted") {
    guard(audience = Some(unsafe(Audience.from("https://api.example"))))
      .verify(bearer(claims()), unsafe(Scopes.parse("read")))
      .map(verified => assertEquals(verified.toOption.map(_.subject.value), Some("user-1")))
  }

  test("an unavailable key set is challenged as invalid_token") {
    new BearerGuard[IO](IO.pure(Left(ParseFailure("Discovery", "down"))), issuer, clockAt(Start))
      .verify(bearer(claims()), Scopes.empty)
      .map(refused => assert(refused.left.toOption.exists(_.header.contains("invalid_token"))))
  }
}
