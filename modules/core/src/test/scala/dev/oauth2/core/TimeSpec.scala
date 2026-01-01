package dev.oauth2.core

import java.time.Duration
import java.time.Instant
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class TimeSpec extends ScalaCheckSuite {

  private val issuedAt: Instant = Instant.parse("2025-01-01T00:00:00Z")

  test("a lifetime must be positive") {
    assert(Lifetime.fromSeconds(1L).isRight)
    assert(Lifetime.fromSeconds(0L).isLeft)
    assert(Lifetime.fromSeconds(-1L).isLeft)
  }

  test("a lifetime of minutes is seconds") {
    assertEquals(Lifetime.fromMinutes(5L).map(_.seconds), Right(300L))
  }

  test("expiry is the issue instant plus the lifetime") {
    assert(Lifetime.fromSeconds(60L).exists(l => Lifetime.expiresAt(issuedAt, l) == issuedAt.plusSeconds(60L)))
  }

  test("a token is expired at its expiry instant and not before") {
    val lifetime = Lifetime.fromSeconds(60L).toOption.get
    val expiry = Lifetime.expiresAt(issuedAt, lifetime)
    assertEquals(Lifetime.isExpired(expiry, issuedAt, lifetime), true)
    assertEquals(Lifetime.isExpired(expiry.minusNanos(1L), issuedAt, lifetime), false)
    assertEquals(Lifetime.isExpired(expiry.plusSeconds(1L), issuedAt, lifetime), true)
  }

  test("the policy holds a lifetime per token type") {
    val policy = LifetimePolicy.defaults
    assertEquals(policy.accessToken.seconds, 3600L)
    assert(policy.refreshToken.seconds > policy.accessToken.seconds)
    assert(policy.authorizationCode.seconds < policy.accessToken.seconds)
  }

  test("the policy resolves the lifetime of a token type") {
    val policy = LifetimePolicy.defaults
    assertEquals(LifetimePolicy.of(policy, TokenType.Access), policy.accessToken)
    assertEquals(LifetimePolicy.of(policy, TokenType.Refresh), policy.refreshToken)
    assertEquals(LifetimePolicy.of(policy, TokenType.AuthorizationCode), policy.authorizationCode)
  }

  test("a fixed clock always answers the same instant") {
    val clock = Clock.constant(issuedAt)
    assertEquals(clock.instant, issuedAt)
    assertEquals(clock.instant, issuedAt)
  }

  test("a test clock advances only when it is advanced") {
    val clock = new TestClock(issuedAt, Duration.ofSeconds(30L))
    assertEquals(clock.instant, issuedAt)
    clock.advance()
    assertEquals(clock.instant, issuedAt.plusSeconds(30L))
    clock.advance(2L)
    assertEquals(clock.instant, issuedAt.plusSeconds(90L))
  }

  test("deterministic entropy answers the same bytes for the same seed") {
    val a = new TestEntropy(7.toByte)
    val b = new TestEntropy(7.toByte)
    assertEquals(a.bytes(16).toVector, b.bytes(16).toVector)
  }

  test("entropy answers as many bytes as asked") {
    val entropy = new TestEntropy(1.toByte)
    assertEquals(entropy.bytes(32).length, 32)
    assert(Entropy.hex(entropy.bytes(4)).length == 8)
  }

  property("expiry is monotone in the lifetime") {
    forAll(Gen.choose(1L, 86400L), Gen.choose(1L, 86400L)) { (a, b) =>
      val la = Lifetime.fromSeconds(a).toOption.get
      val lb = Lifetime.fromSeconds(b).toOption.get
      (a <= b) == !Lifetime.expiresAt(issuedAt, la).isAfter(Lifetime.expiresAt(issuedAt, lb))
    }
  }

  property("a token is never expired before it is issued") {
    forAll(Gen.choose(1L, 86400L)) { seconds =>
      val lifetime = Lifetime.fromSeconds(seconds).toOption.get
      !Lifetime.isExpired(issuedAt, issuedAt, lifetime)
    }
  }

  property("hex encoding is two characters per byte") {
    forAll(Gen.choose(1, 32)) { n =>
      Entropy.hex(new TestEntropy(3.toByte).bytes(n)).length == n * 2
    }
  }
}
