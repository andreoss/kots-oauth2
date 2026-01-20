package kots.oauth2.store.memory

import java.time.Instant

import cats.effect.IO
import cats.effect.Ref
import kots.oauth2.core.Clock
import munit.CatsEffectSuite

class MemoryRateLimiterSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def setup(limit: Int, window: Long): IO[(InMemoryRateLimiter[IO], Ref[IO, Instant])] =
    for {
      moment <- Ref.of[IO, Instant](Start)
      clock = new Clock[IO] { def instant: IO[Instant] = moment.get }
      limiter <- InMemoryRateLimiter.create[IO](clock, limit, window)
    } yield (limiter, moment)

  test("requests inside the limit pass and the next one is refused with the wait") {
    for {
      pair <- setup(limit = 2, window = 60L)
      (limiter, _) = pair
      first <- limiter.acquire("client-1")
      second <- limiter.acquire("client-1")
      third <- limiter.acquire("client-1")
    } yield {
      assertEquals(first, None)
      assertEquals(second, None)
      assertEquals(third, Some(60L))
    }
  }

  test("an elapsed window opens a fresh allowance") {
    for {
      pair <- setup(limit = 1, window = 60L)
      (limiter, moment) = pair
      _ <- limiter.acquire("client-1")
      refused <- limiter.acquire("client-1")
      _ <- moment.set(Start.plusSeconds(60L))
      renewed <- limiter.acquire("client-1")
    } yield {
      assert(refused.isDefined)
      assertEquals(renewed, None)
    }
  }

  test("keys are counted independently") {
    for {
      pair <- setup(limit = 1, window = 60L)
      (limiter, _) = pair
      _ <- limiter.acquire("client-1")
      other <- limiter.acquire("client-2")
      refused <- limiter.acquire("client-1")
    } yield {
      assertEquals(other, None)
      assert(refused.isDefined)
    }
  }

  test("the advertised wait shrinks as the window ages and never reaches zero") {
    for {
      pair <- setup(limit = 1, window = 60L)
      (limiter, moment) = pair
      _ <- limiter.acquire("client-1")
      _ <- moment.set(Start.plusSeconds(45L))
      aged <- limiter.acquire("client-1")
      _ <- moment.set(Start.plusSeconds(59L).plusMillis(900L))
      edge <- limiter.acquire("client-1")
    } yield {
      assertEquals(aged, Some(15L))
      assertEquals(edge, Some(1L))
    }
  }
}
