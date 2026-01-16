package dev.oauth2.host

import cats.effect.IO
import dev.oauth2.http.Server
import dev.oauth2.store.memory.InMemoryMetrics
import munit.CatsEffectSuite
import org.http4s.Method
import org.http4s.Request
import org.http4s.Status
import org.http4s.Uri

class MeasuredSpec extends CatsEffectSuite {

  private def request(path: String): Request[IO] =
    Request[IO](method = Method.GET, uri = Uri.unsafeFromString(s"http://localhost$path"))

  test("an answered request is counted with its path, status and latency") {
    for {
      metrics <- InMemoryMetrics.create[IO]
      measured = Measured(metrics, Interpreter.routes[IO](List(Server.health[IO])))
      first <- measured.run(request("/health")).value
      _ <- measured.run(request("/health")).value
      counters <- metrics.counters
    } yield {
      assertEquals(first.map(_.status), Some(Status.Ok))
      val (count, nanos) = counters(("/health", 200))
      assertEquals(count, 2L)
      assert(nanos >= 0L)
      assertEquals(counters.size, 1)
    }
  }

  test("an unmatched request is not observed") {
    for {
      metrics <- InMemoryMetrics.create[IO]
      measured = Measured(metrics, Interpreter.routes[IO](List(Server.health[IO])))
      missed <- measured.run(request("/absent")).value
      counters <- metrics.counters
    } yield {
      assertEquals(missed, None)
      assertEquals(counters, Map.empty[(String, Int), (Long, Long)])
    }
  }
}
