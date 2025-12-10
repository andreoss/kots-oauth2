package dev.oauth2.server

import cats.MonadThrow
import cats.syntax.applicativeError._
import cats.syntax.functor._
import cats.syntax.traverse._

import dev.oauth2.http.HealthReport
import dev.oauth2.http.ReadinessLogic

final class Readiness[F[_]: MonadThrow](probes: List[(String, F[Boolean])]) extends ReadinessLogic[F] {

  def report: F[HealthReport] =
    probes
      .traverse { case (name, probe) =>
        probe.handleError(_ => false).map(alive => name -> alive)
      }
      .map(HealthReport(_))
}
