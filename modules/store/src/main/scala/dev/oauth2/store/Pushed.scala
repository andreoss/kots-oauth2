package dev.oauth2.store

import java.time.Instant

import dev.oauth2.core.ClientId
import dev.oauth2.core.RequestUri

final case class PushedRequest(
    uri: RequestUri,
    clientId: ClientId,
    parameters: Map[String, String],
    expiresAt: Instant
) {
  def isExpired(now: Instant): Boolean = !now.isBefore(expiresAt)
}

trait PushedRequestStore[F[_]] {

  def save(record: PushedRequest): F[Unit]

  def consume(uri: RequestUri): F[Option[PushedRequest]]

  def sweep: F[Int]
}
