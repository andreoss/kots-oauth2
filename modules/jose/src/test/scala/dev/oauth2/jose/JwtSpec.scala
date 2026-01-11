package dev.oauth2.jose

import java.time.Instant
import java.util.Base64

import dev.oauth2.core.Audience
import dev.oauth2.core.ClientId
import dev.oauth2.core.Issuer
import dev.oauth2.core.JwtId
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import munit.FunSuite

class JwtSpec extends FunSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[dev.oauth2.core.ParseFailure, A]): A = Fakes.unsafe(parsed)

  private val published: Jwks = Jwks(List(Fakes.signingJwk))

  private val claims: JwtClaims = JwtClaims(
    issuer = unsafe(Issuer.from("https://server.example")),
    subject = unsafe(Subject.from("user-1")),
    audience = Some(unsafe(Audience.from("https://api.example"))),
    clientId = unsafe(ClientId.from("client-1")),
    scopes = unsafe(Scopes.parse("read write")),
    issuedAt = Start,
    expiresAt = Start.plusSeconds(3600L),
    tokenId = unsafe(JwtId.from("jwt-1"))
  )

  test("an issued access token verifies and round trips its claims") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    assertEquals(Jwt.claims(compact, published, Start), Right(claims))
  }

  test("the access token header carries the at jwt type") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    val header = new String(Base64.getUrlDecoder.decode(compact.split('.')(0)), "UTF-8")
    val cursor = io.circe.parser.parse(header).toOption.get.hcursor
    assertEquals(cursor.get[String]("typ").toOption, Some("at+jwt"))
  }

  test("an expired access token is refused") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    assert(Jwt.claims(compact, published, Start.plusSeconds(3600L)).isLeft)
    assert(Jwt.claims(compact, published, Start.plusSeconds(3599L)).isRight)
  }

  test("a token without an audience or scopes omits the claims") {
    val bare = claims.copy(audience = None, scopes = Scopes.empty)
    val compact = Jwt.issue(Fakes.signingKey, bare).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    val cursor = io.circe.parser.parse(payload).toOption.get.hcursor
    assertEquals(cursor.keys.map(_.toSet), Some(Set("iss", "sub", "client_id", "jti", "iat", "exp")))
    assertEquals(Jwt.claims(compact, published, Start), Right(bare))
  }

  test("a jws of another type is not an access token") {
    val compact = Jws
      .sign(Alg.RS256, Fakes.keyId("key-1"), Fakes.signingPair.getPrivate, """{"sub":"user-1"}""")
      .toOption
      .get
    assert(Jwt.claims(compact, published, Start).isLeft)
  }

  test("an access token signed by an unpublished key is refused") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    assert(Jwt.claims(compact, Jwks(List(Fakes.rsa("key-1"))), Start).isLeft)
  }
}
