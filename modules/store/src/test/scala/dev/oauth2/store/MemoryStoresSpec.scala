package dev.oauth2.store.memory

import java.time.Duration
import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.AccessToken
import dev.oauth2.core.AccessTokenHash
import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Clock
import dev.oauth2.core.GrantId
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.RefreshTokenHash
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TestClock
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.Grant
import dev.oauth2.store.TokenRecord
import munit.CatsEffectSuite

class MemoryStoresSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def clockOf(test: TestClock): Clock[IO] =
    new Clock[IO] {
      def instant: IO[Instant] = IO(test.instant)
    }

  private val client = Client(
    id = unsafe(ClientId.from("client-1")),
    redirectUris = Set.empty,
    scopes = unsafe(Scopes.parse("read")),
    authMethod = ClientAuthMethod.ClientSecretBasic,
    secretHash = Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private def code(name: String, expiresAt: Instant): CodeRecord =
    CodeRecord(
      code = unsafe(AuthorizationCode.from(name)),
      clientId = client.id,
      redirectUri = unsafe(dev.oauth2.core.RedirectUri.from("https://client.example/cb")),
      subject = unsafe(Subject.from("user-1")),
      scopes = unsafe(Scopes.parse("read")),
      details = AuthorizationDetails.empty,
      pkce = None,
      expiresAt = expiresAt
    )

  private def token(access: String, refresh: Option[String], grant: String): TokenRecord =
    TokenRecord(
      accessTokenHash = AccessTokenHash.of(unsafe(AccessToken.from(access))),
      refreshTokenHash = refresh.map(raw => RefreshTokenHash.of(unsafe(RefreshToken.from(raw)))),
      grantId = unsafe(GrantId.from(grant)),
      clientId = client.id,
      subject = unsafe(Subject.from("user-1")),
      scopes = unsafe(Scopes.parse("read")),
      details = AuthorizationDetails.empty,
      issuedAt = start,
      accessExpiresAt = start.plusSeconds(60L),
      refreshExpiresAt = refresh.map(_ => start.plusSeconds(3600L))
    )

  private def grant(name: String): Grant =
    Grant(unsafe(GrantId.from(name)), client.id, unsafe(Subject.from("user-1")), unsafe(Scopes.parse("read")), AuthorizationDetails.empty, revoked = false)

  test("a registered client is found and an unknown one is not") {
    for {
      store <- InMemoryClientStore.create[IO](List(client))
      found <- store.find(client.id)
      other <- store.find(unsafe(ClientId.from("client-2")))
    } yield {
      assertEquals(found, Some(client))
      assertEquals(other, None)
    }
  }

  test("a saved code is consumed once and refused afterwards") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryCodeStore.create[IO](clockOf(clock))
      _ <- store.save(code("code-1", start.plusSeconds(60L)))
      first <- store.consume(unsafe(AuthorizationCode.from("code-1")))
      second <- store.consume(unsafe(AuthorizationCode.from("code-1")))
    } yield {
      assertEquals(first.map(_.code.value), Some("code-1"))
      assertEquals(second, None)
    }
  }

  test("a redeemed code remembers the grant it issued") {
    val grant = unsafe(GrantId.from("grant-1"))
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryCodeStore.create[IO](clockOf(clock))
      before <- store.redeemed(unsafe(AuthorizationCode.from("code-1")))
      _ <- store.redeem(unsafe(AuthorizationCode.from("code-1")), grant)
      after <- store.redeemed(unsafe(AuthorizationCode.from("code-1")))
    } yield {
      assertEquals(before, None)
      assertEquals(after, Some(grant))
    }
  }

  test("a code redeemed twice keeps the last grant") {
    val first = unsafe(GrantId.from("grant-1"))
    val second = unsafe(GrantId.from("grant-2"))
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryCodeStore.create[IO](clockOf(clock))
      _ <- store.redeem(unsafe(AuthorizationCode.from("code-1")), first)
      _ <- store.redeem(unsafe(AuthorizationCode.from("code-1")), second)
      found <- store.redeemed(unsafe(AuthorizationCode.from("code-1")))
    } yield assertEquals(found, Some(second))
  }

  test("an unknown code is never consumed") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryCodeStore.create[IO](clockOf(clock))
      found <- store.consume(unsafe(AuthorizationCode.from("absent")))
    } yield assertEquals(found, None)
  }

  test("a code is refused at its expiry instant and before it is granted") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryCodeStore.create[IO](clockOf(clock))
      _ <- store.save(code("code-1", start.plusSeconds(60L)))
      before <- store.consume(unsafe(AuthorizationCode.from("code-1")))
      _ <- store.save(code("code-2", start.plusSeconds(60L)))
      _ <- IO(clock.advance())
      atExpiry <- store.consume(unsafe(AuthorizationCode.from("code-2")))
    } yield {
      assert(before.isDefined)
      assertEquals(atExpiry, None)
    }
  }

  test("an expired code is purged and stays refused") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryCodeStore.create[IO](clockOf(clock))
      _ <- store.save(code("code-1", start.plusSeconds(60L)))
      _ <- IO(clock.advance(2L))
      after <- store.consume(unsafe(AuthorizationCode.from("code-1")))
      _ <- store.save(code("code-1", start.plusSeconds(600L)))
      replaced <- store.consume(unsafe(AuthorizationCode.from("code-1")))
    } yield {
      assertEquals(after, None)
      assertEquals(replaced.map(_.expiresAt), Some(start.plusSeconds(600L)))
    }
  }

  test("a saved grant is found, revoked once and stays revoked") {
    for {
      store <- InMemoryGrantStore.create[IO]
      _ <- store.save(grant("grant-1"))
      found <- store.find(unsafe(GrantId.from("grant-1")))
      _ <- store.revoke(unsafe(GrantId.from("grant-1")))
      revoked <- store.find(unsafe(GrantId.from("grant-1")))
      _ <- store.revoke(unsafe(GrantId.from("grant-1")))
      twice <- store.find(unsafe(GrantId.from("grant-1")))
    } yield {
      assertEquals(found.map(_.revoked), Some(false))
      assertEquals(revoked.map(_.revoked), Some(true))
      assertEquals(twice.map(_.revoked), Some(true))
    }
  }

  test("revoking an unknown grant adds nothing to the store") {
    for {
      store <- InMemoryGrantStore.create[IO]
      _ <- store.revoke(unsafe(GrantId.from("absent")))
      found <- store.find(unsafe(GrantId.from("absent")))
    } yield assertEquals(found, None)
  }

  test("a saved token is found by its access token and by its refresh token") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(token("at-1", Some("rt-1"), "grant-1"))
      byAccess <- store.findByAccess(unsafe(AccessToken.from("at-1")))
      byRefresh <- store.findByRefresh(unsafe(RefreshToken.from("rt-1")))
    } yield {
      assertEquals(byAccess.map(_.grantId.value), Some("grant-1"))
      assertEquals(byRefresh.map(_.grantId.value), Some("grant-1"))
    }
  }

  test("a stored record carries the hash and not the token itself") {
    val record = token("at-1", Some("rt-1"), "grant-1")
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(record)
      found <- store.findByAccess(unsafe(AccessToken.from("at-1")))
    } yield {
      assertNotEquals(found.map(_.accessTokenHash.value), Some("at-1"))
      assert(found.exists(_.matchesAccess(unsafe(AccessToken.from("at-1")))))
      assert(found.exists(_.matchesRefresh(unsafe(RefreshToken.from("rt-1")))))
    }
  }

  test("a token is not found by another token") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(token("at-1", Some("rt-1"), "grant-1"))
      byAccess <- store.findByAccess(unsafe(AccessToken.from("at-2")))
      byRefresh <- store.findByRefresh(unsafe(RefreshToken.from("rt-2")))
    } yield {
      assertEquals(byAccess, None)
      assertEquals(byRefresh, None)
    }
  }

  test("an expired access token is not found and is dropped") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(token("at-1", Some("rt-1"), "grant-1"))
      _ <- IO(clock.advance())
      byAccess <- store.findByAccess(unsafe(AccessToken.from("at-1")))
      byRefresh <- store.findByRefresh(unsafe(RefreshToken.from("rt-1")))
    } yield {
      assertEquals(byAccess, None)
      assertEquals(byRefresh, None)
    }
  }

  test("an expired refresh token is not found while the access token lives") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(3600L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(token("at-1", Some("rt-1"), "grant-1"))
      byRefresh <- store.findByRefresh(unsafe(RefreshToken.from("rt-1")))
      _ <- IO(clock.advance())
      expired <- store.findByRefresh(unsafe(RefreshToken.from("rt-1")))
    } yield {
      assert(byRefresh.isDefined)
      assertEquals(expired, None)
    }
  }

  test("a token without a refresh token is never found by refresh") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(token("at-1", None, "grant-1"))
      byRefresh <- store.findByRefresh(unsafe(RefreshToken.from("rt-1")))
      byAccess <- store.findByAccess(unsafe(AccessToken.from("at-1")))
    } yield {
      assertEquals(byRefresh, None)
      assert(byAccess.isDefined)
    }
  }

  test("dropping a refresh token removes the record and an unknown drop does not") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(token("at-1", Some("rt-1"), "grant-1"))
      _ <- store.save(token("at-2", Some("rt-2"), "grant-1"))
      _ <- store.drop(unsafe(RefreshToken.from("absent")))
      kept <- store.findByAccess(unsafe(AccessToken.from("at-1")))
      _ <- store.drop(unsafe(RefreshToken.from("rt-1")))
      dropped <- store.findByAccess(unsafe(AccessToken.from("at-1")))
      other <- store.findByAccess(unsafe(AccessToken.from("at-2")))
    } yield {
      assert(kept.isDefined)
      assertEquals(dropped, None)
      assert(other.isDefined)
    }
  }

  test("revoking a grant removes every token of that grant and keeps the others") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(token("at-1", Some("rt-1"), "grant-1"))
      _ <- store.save(token("at-2", Some("rt-2"), "grant-1"))
      _ <- store.save(token("at-3", Some("rt-3"), "grant-2"))
      _ <- store.revokeGrant(unsafe(GrantId.from("grant-1")))
      first <- store.findByAccess(unsafe(AccessToken.from("at-1")))
      firstRefresh <- store.findByRefresh(unsafe(RefreshToken.from("rt-1")))
      second <- store.findByAccess(unsafe(AccessToken.from("at-2")))
      third <- store.findByAccess(unsafe(AccessToken.from("at-3")))
    } yield {
      assertEquals(first, None)
      assertEquals(firstRefresh, None)
      assertEquals(second, None)
      assert(third.isDefined)
    }
  }

  test("a saved token replaces a record with the same access token") {
    for {
      clock <- IO(new TestClock(start, Duration.ofSeconds(60L)))
      store <- InMemoryTokenStore.create[IO](clockOf(clock))
      _ <- store.save(token("at-1", Some("rt-1"), "grant-1"))
      _ <- store.save(token("at-1", Some("rt-2"), "grant-2"))
      byOld <- store.findByRefresh(unsafe(RefreshToken.from("rt-1")))
      byNew <- store.findByRefresh(unsafe(RefreshToken.from("rt-2")))
    } yield {
      assertEquals(byOld, None)
      assertEquals(byNew.map(_.grantId.value), Some("grant-2"))
    }
  }
}
