package dev.oauth2.store.memory

import cats.effect.IO
import dev.oauth2.store.Observation
import munit.CatsEffectSuite

class MemoryMetricsSpec extends CatsEffectSuite {

  test("observations are counted and their latency accumulated per endpoint and status") {
    for {
      metrics <- InMemoryMetrics.create[IO]
      _ <- metrics.observed(Observation("/token", 200, 5L))
      _ <- metrics.observed(Observation("/token", 200, 7L))
      _ <- metrics.observed(Observation("/token", 400, 3L))
      counters <- metrics.counters
    } yield {
      assertEquals(counters.get(("/token", 200)), Some((2L, 12L)))
      assertEquals(counters.get(("/token", 400)), Some((1L, 3L)))
      assertEquals(counters.get(("/jwks", 200)), None)
    }
  }
}
