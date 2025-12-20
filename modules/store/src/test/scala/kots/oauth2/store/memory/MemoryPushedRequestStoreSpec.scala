package kots.oauth2.store.memory

import java.time.Duration
import java.time.Instant

import cats.effect.IO
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RequestUri
import kots.oauth2.core.TestClock
import kots.oauth2.store.PushedRequest
import munit.CatsEffectSuite

class MemoryPushedRequestStoreSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val uri: RequestUri = unsafe(RequestUri.from(RequestUri.Prefix + "abc"))

  private def record(expiresAt: Instant): PushedRequest =
    PushedRequest(uri, unsafe(ClientId.from("client-1")), Map("client_id" -> "client-1"), expiresAt)

  private def clockOf(test: TestClock): Clock[IO] =
    new Clock[IO] {
      def instant: IO[Instant] = IO(test.instant)
    }

  test("a pushed request is consumed exactly once") {
    for {
      pushed <- InMemoryPushedRequestStore.create[IO](clockOf(new TestClock(start, Duration.ofSeconds(1L))))
      _ <- pushed.save(record(start.plusSeconds(60L)))
      first <- pushed.consume(uri)
      second <- pushed.consume(uri)
    } yield {
      assertEquals(first.map(_.uri), Some(uri))
      assertEquals(second, None)
    }
  }

  test("an expired pushed request consumes to nothing") {
    for {
      pushed <- InMemoryPushedRequestStore.create[IO](clockOf(new TestClock(start, Duration.ofSeconds(1L))))
      _ <- pushed.save(record(start))
      taken <- pushed.consume(uri)
    } yield assertEquals(taken, None)
  }
}
