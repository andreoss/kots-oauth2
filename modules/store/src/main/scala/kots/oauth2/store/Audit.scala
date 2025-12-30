package kots.oauth2.store

import cats.Applicative

import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.GrantType
import kots.oauth2.core.Subject

sealed abstract class AuditEvent(val name: String)

object AuditEvent {

  final case class Issued(clientId: ClientId, subject: Subject, grantId: GrantId, grant: GrantType)
      extends AuditEvent("issued")

  final case class Refreshed(clientId: ClientId, subject: Subject, grantId: GrantId)
      extends AuditEvent("refreshed")

  final case class Revoked(clientId: ClientId, grantId: GrantId) extends AuditEvent("revoked")

  final case class Introspected(clientId: ClientId, active: Boolean) extends AuditEvent("introspected")

  final case class AuthenticationFailed(clientId: Option[ClientId])
      extends AuditEvent("authentication_failed")

  final case class AssertionReplayed(clientId: ClientId) extends AuditEvent("assertion_replayed")
}

trait AuditLog[F[_]] {

  def record(event: AuditEvent): F[Unit]
}

object AuditLog {

  def noop[F[_]: Applicative]: AuditLog[F] =
    new AuditLog[F] {
      def record(event: AuditEvent): F[Unit] = Applicative[F].unit
    }
}
