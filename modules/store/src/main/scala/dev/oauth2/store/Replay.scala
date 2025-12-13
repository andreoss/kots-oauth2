package dev.oauth2.store

import java.time.Instant

import dev.oauth2.core.JwtId

trait ReplayStore[F[_]] {

  def record(id: JwtId, expiresAt: Instant): F[Boolean]

  def sweep: F[Int]
}
