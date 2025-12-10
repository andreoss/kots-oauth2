package dev.oauth2.http

import io.circe.Json

final case class HealthReport(dependencies: List[(String, Boolean)]) {

  def healthy: Boolean = dependencies.forall { case (_, alive) => alive }
}

object HealthReport {

  val Ok: String = "ok"

  val Unavailable: String = "unavailable"

  def render(report: HealthReport): Map[String, Json] =
    Map(
      "status" -> Json.fromString(if (report.healthy) Ok else Unavailable),
      "dependencies" -> Json.fromFields(report.dependencies.map { case (name, alive) =>
        name -> Json.fromBoolean(alive)
      })
    )
}
