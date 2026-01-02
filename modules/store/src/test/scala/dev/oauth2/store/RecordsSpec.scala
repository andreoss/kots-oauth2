package dev.oauth2.store

import java.time.Instant

import dev.oauth2.core.AccessToken
import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientId
import dev.oauth2.core.CodeChallenge
import dev.oauth2.core.CodeChallengeMethod
import dev.oauth2.core.CodeVerifier
import dev.oauth2.core.GrantId
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.Scope
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class RecordsSpec extends ScalaCheckSuite {

  private def unsafe[A](parsed: Either[dev.oauth2.core.ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val registered: Set[RedirectUri] =
    Set(unsafe(RedirectUri.from("https://client.example/cb")), unsafe(RedirectUri.from("http://127.0.0.1:8080/cb")))

  private val client = Client(
    id = unsafe(ClientId.from("client-1")),
    redirectUris = registered,
    scopes = unsafe(Scopes.parse("openid read")),
    confidential = true
  )

  private val expiresAt: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val code = CodeRecord(
    code = unsafe(AuthorizationCode.from("code-1")),
    clientId = client.id,
    redirectUri = unsafe(RedirectUri.from("https://client.example/cb")),
    subject = unsafe(Subject.from("user-1")),
    scopes = unsafe(Scopes.parse("read")),
    details = AuthorizationDetails.empty,
    pkce = Some(
      Pkce(
        unsafe(CodeChallenge.from("a" * 43)),
        CodeChallengeMethod.S256
      )
    ),
    expiresAt = expiresAt
  )

  private val token = TokenRecord(
    accessToken = unsafe(AccessToken.from("at-1")),
    refreshToken = Some(unsafe(RefreshToken.from("rt-1"))),
    grantId = unsafe(GrantId.from("grant-1")),
    clientId = client.id,
    subject = unsafe(Subject.from("user-1")),
    scopes = unsafe(Scopes.parse("read")),
    details = AuthorizationDetails.empty,
    issuedAt = expiresAt.minusSeconds(60L),
    accessExpiresAt = expiresAt,
    refreshExpiresAt = Some(expiresAt.plusSeconds(3600L))
  )

  private val instant: Gen[Instant] =
    Gen.choose(-100000L, 100000L).map(Instant.parse("2025-01-01T00:00:00Z").plusSeconds)

  test("a client allows a registered redirect uri and refuses any other") {
    assert(client.allowsRedirect(unsafe(RedirectUri.from("https://client.example/cb"))))
    assertEquals(client.allowsRedirect(unsafe(RedirectUri.from("https://evil.example/cb"))), false)
  }

  test("a client tolerates a loopback port change") {
    assert(client.allowsRedirect(unsafe(RedirectUri.from("http://127.0.0.1:9090/cb"))))
    assertEquals(client.allowsRedirect(unsafe(RedirectUri.from("http://localhost:8080/other"))), false)
  }

  test("a client allows a requested scope subset and refuses a superset") {
    assert(client.allowsScopes(unsafe(Scopes.parse("read"))))
    assert(client.allowsScopes(Scopes.empty))
    assertEquals(client.allowsScopes(unsafe(Scopes.parse("read write"))), false)
  }

  test("a scope refused by the client is not in its own scope set") {
    val extra = unsafe(Scope.from("write"))
    assertEquals(Scopes.contains(client.scopes, extra), false)
  }

  test("a code is not expired before its expiry instant and expired at it") {
    assertEquals(code.isExpired(expiresAt.minusNanos(1L)), false)
    assertEquals(code.isExpired(expiresAt), true)
    assertEquals(code.isExpired(expiresAt.plusSeconds(1L)), true)
  }

  test("an access token is expired at its expiry instant and not before") {
    assertEquals(token.isAccessExpired(expiresAt.minusNanos(1L)), false)
    assertEquals(token.isAccessExpired(expiresAt), true)
  }

  test("a refresh token without expiry is expired") {
    assertEquals(token.copy(refreshExpiresAt = None).isRefreshExpired(expiresAt), true)
  }

  test("a refresh token is expired at its expiry instant and not before") {
    val expiry = expiresAt.plusSeconds(3600L)
    assertEquals(token.isRefreshExpired(expiry.minusNanos(1L)), false)
    assertEquals(token.isRefreshExpired(expiry), true)
  }

  test("a code without a challenge stays without one") {
    assertEquals(code.copy(pkce = None).pkce, None)
  }

  test("a revocable grant carries its revoked flag") {
    val grant = Grant(token.grantId, client.id, token.subject, token.scopes, AuthorizationDetails.empty, revoked = false)
    assertEquals(grant.copy(revoked = true).revoked, true)
    assertEquals(grant.revoked, false)
  }

  property("expiry is monotone in the current instant") {
    forAll(instant, instant) { (a, b) =>
      val earlier = if (a.isBefore(b)) a else b
      val later = if (a.isBefore(b)) b else a
      (!code.isExpired(earlier) || code.isExpired(later)) &&
      (!token.isAccessExpired(earlier) || token.isAccessExpired(later))
    }
  }

  property("a code verifier and its challenge are carried by the record") {
    forAll(Gen.const("b" * 43)) { raw =>
      val verifier = unsafe(CodeVerifier.from(raw))
      code.copy(pkce = Some(Pkce(unsafe(CodeChallenge.from(verifier.value)), CodeChallengeMethod.Plain))).pkce
        .exists(_.challenge.value == raw)
    }
  }
}
