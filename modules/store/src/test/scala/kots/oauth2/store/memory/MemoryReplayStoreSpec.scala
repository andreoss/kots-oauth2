package kots.oauth2.store.memory

import java.time.Duration
import java.time.Instant

import cats.effect.IO
import kots.oauth2.core.Clock
import kots.oauth2.core.JwtId
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.TestClock
import munit.CatsEffectSuite

class MemoryReplayStoreSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val id: JwtId = unsafe(JwtId.from("jti-1"))

  test("a token id is recorded once and refused while it lives") {
    val test = new TestClock(start, Duration.ofSeconds(1L))
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO(test.instant)
    }
    for {
      replays <- InMemoryReplayStore.create[IO](clock)
      first <- replays.record(id, start.plusSeconds(60L))
      second <- replays.record(id, start.plusSeconds(60L))
    } yield {
      assertEquals(first, true)
      assertEquals(second, false)
    }
  }

  test("an expired token id is forgotten") {
    val test = new TestClock(start, Duration.ofSeconds(1L))
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO(test.instant)
    }
    for {
      replays <- InMemoryReplayStore.create[IO](clock)
      _ <- replays.record(id, start.plusSeconds(30L))
      _ <- IO(test.advance(31L))
      again <- replays.record(id, start.plusSeconds(90L))
    } yield assertEquals(again, true)
  }
}
