package dev.oauth2.store

import java.time.Instant

import dev.oauth2.core.ClientId
import dev.oauth2.core.DeviceCode
import dev.oauth2.core.ResourceIndicator
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.UserCode

final case class DeviceRecord(
    deviceCode: DeviceCode,
    userCode: UserCode,
    clientId: ClientId,
    scopes: Scopes,
    expiresAt: Instant,
    subject: Option[Subject],
    denied: Boolean,
    lastPolledAt: Option[Instant],
    resource: Option[ResourceIndicator] = None
) {

  def isExpired(now: Instant): Boolean = !now.isBefore(expiresAt)

  def decided: Boolean = denied || subject.isDefined
}

trait DeviceStore[F[_]] {

  def save(record: DeviceRecord): F[Unit]

  def approve(userCode: UserCode, subject: Subject): F[Boolean]

  def deny(userCode: UserCode): F[Boolean]

  def poll(deviceCode: DeviceCode): F[Option[DeviceRecord]]

  def consume(deviceCode: DeviceCode): F[Option[DeviceRecord]]

  def sweep: F[Int]
}
