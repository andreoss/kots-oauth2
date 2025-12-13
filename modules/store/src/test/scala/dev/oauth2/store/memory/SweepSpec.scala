package dev.oauth2.store.memory

import java.time.Duration
import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.AccessToken
import dev.oauth2.core.AccessTokenHash
import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientId
import dev.oauth2.core.Clock
import dev.oauth2.core.DeviceCode
import dev.oauth2.core.GrantId
import dev.oauth2.core.JwtId
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.RequestUri
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TestClock
import dev.oauth2.core.UserCode
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.DeviceRecord
import dev.oauth2.store.PushedRequest
import dev.oauth2.store.TokenRecord
import munit.CatsEffectSuite

class SweepSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def clockOf(test: TestClock): Clock[IO] =
    new Clock[IO] {
      def instant: IO[Instant] = IO(test.instant)
    }

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private def code(name: String, expiresAt: Instant): CodeRecord =
    CodeRecord(
      code = unsafe(AuthorizationCode.from(name)),
      clientId = clientId,
      redirectUri = unsafe(RedirectUri.from("https://client.example/cb")),
      subject = unsafe(Subject.from("user-1")),
      scopes = unsafe(Scopes.parse("read")),
      details = AuthorizationDetails.empty,
      pkce = None,
      expiresAt = expiresAt
    )

  private def token(name: String, accessExpiresAt: Instant): TokenRecord =
    TokenRecord(
      accessTokenHash = AccessTokenHash.of(unsafe(AccessToken.from(name))),
      refreshTokenHash = None,
      grantId = unsafe(GrantId.from(s"grant-$name")),
      clientId = clientId,
      subject = unsafe(Subject.from("user-1")),
      scopes = unsafe(Scopes.parse("read")),
      details = AuthorizationDetails.empty,
      issuedAt = start,
      accessExpiresAt = accessExpiresAt,
      refreshExpiresAt = None
    )

  private def device(name: String, user: String, expiresAt: Instant): DeviceRecord =
    DeviceRecord(
      deviceCode = unsafe(DeviceCode.from(name)),
      userCode = unsafe(UserCode.from(user)),
      clientId = clientId,
      scopes = unsafe(Scopes.parse("read")),
      expiresAt = expiresAt,
      subject = None,
      denied = false,
      lastPolledAt = None
    )

  test("sweeping a code store drops only the expired records") {
    val clock = clockOf(new TestClock(start, Duration.ofSeconds(1L)))
    for {
      codes <- InMemoryCodeStore.create[IO](clock)
      _ <- codes.save(code("code-live", start.plusSeconds(60L)))
      _ <- codes.save(code("code-dead", start))
      swept <- codes.sweep
      live <- codes.consume(unsafe(AuthorizationCode.from("code-live")))
    } yield {
      assertEquals(swept, 1)
      assert(live.isDefined)
    }
  }

  test("sweeping a token store drops records whose every lifetime has passed") {
    val clock = clockOf(new TestClock(start, Duration.ofSeconds(1L)))
    for {
      tokens <- InMemoryTokenStore.create[IO](clock)
      _ <- tokens.save(token("at-live", start.plusSeconds(60L)))
      _ <- tokens.save(token("at-dead", start))
      swept <- tokens.sweep
      live <- tokens.findByAccess(unsafe(AccessToken.from("at-live")))
    } yield {
      assertEquals(swept, 1)
      assert(live.isDefined)
    }
  }

  test("sweeping a device store drops the expired authorizations") {
    val clock = clockOf(new TestClock(start, Duration.ofSeconds(1L)))
    for {
      devices <- InMemoryDeviceStore.create[IO](clock)
      _ <- devices.save(device("device-live", "BCDF-GHJK", start.plusSeconds(60L)))
      _ <- devices.save(device("device-dead", "MNPQ-RSTV", start))
      swept <- devices.sweep
      live <- devices.poll(unsafe(DeviceCode.from("device-live")))
    } yield {
      assertEquals(swept, 1)
      assert(live.isDefined)
    }
  }

  test("sweeping the pushed requests drops what has passed") {
    val clock = clockOf(new TestClock(start, Duration.ofSeconds(1L)))
    for {
      pushed <- InMemoryPushedRequestStore.create[IO](clock)
      _ <- pushed.save(
        PushedRequest(unsafe(RequestUri.from(RequestUri.Prefix + "live")), clientId, Map.empty, start.plusSeconds(60L))
      )
      _ <- pushed.save(
        PushedRequest(unsafe(RequestUri.from(RequestUri.Prefix + "dead")), clientId, Map.empty, start)
      )
      swept <- pushed.sweep
    } yield assertEquals(swept, 1)
  }

  test("sweeping the replays forgets the passed token ids") {
    val ticking = new TestClock(start, Duration.ofSeconds(1L))
    for {
      replays <- InMemoryReplayStore.create[IO](clockOf(ticking))
      _ <- replays.record(unsafe(JwtId.from("jti-live")), start.plusSeconds(60L))
      _ <- replays.record(unsafe(JwtId.from("jti-dead")), start.plusSeconds(1L))
      _ <- IO(ticking.advance(2L))
      swept <- replays.sweep
      fresh <- replays.record(unsafe(JwtId.from("jti-dead")), start.plusSeconds(60L))
    } yield {
      assertEquals(swept, 1)
      assertEquals(fresh, true)
    }
  }
}
