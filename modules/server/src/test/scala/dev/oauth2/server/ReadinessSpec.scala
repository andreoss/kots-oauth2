package dev.oauth2.server

import cats.effect.IO
import dev.oauth2.http.HealthReport
import munit.CatsEffectSuite

class ReadinessSpec extends CatsEffectSuite {

  test("a readiness report names every dependency with its probe answer") {
    val readiness = new Readiness[IO](
      List(
        "clients" -> IO.pure(true),
        "tokens" -> IO.pure(false)
      )
    )
    readiness.report.map { report =>
      assertEquals(report.dependencies, List("clients" -> true, "tokens" -> false))
      assertEquals(report.healthy, false)
    }
  }

  test("a report with every probe green is healthy") {
    new Readiness[IO](List("clients" -> IO.pure(true))).report
      .map(report => assertEquals(report.healthy, true))
  }

  test("a probe failure counts as an unhealthy dependency") {
    new Readiness[IO](List("clients" -> IO.raiseError(new IllegalStateException("down")))).report
      .map { report =>
        assertEquals(report.dependencies, List("clients" -> false))
        assertEquals(report.healthy, false)
      }
  }

  test("the report renders a status and one field per dependency") {
    val rendered = HealthReport.render(HealthReport(List("clients" -> true, "tokens" -> false)))
    assertEquals(rendered("status"), io.circe.Json.fromString("unavailable"))
    val dependencies = rendered("dependencies").hcursor
    assertEquals(dependencies.get[Boolean]("clients").toOption, Some(true))
    assertEquals(dependencies.get[Boolean]("tokens").toOption, Some(false))
    assertEquals(
      HealthReport.render(HealthReport(List("clients" -> true)))("status"),
      io.circe.Json.fromString("ok")
    )
  }
}
