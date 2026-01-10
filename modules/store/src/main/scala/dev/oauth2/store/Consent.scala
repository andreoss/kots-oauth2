package dev.oauth2.store

import dev.oauth2.core.ClientId
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject

final case class ConsentRecord(clientId: ClientId, subject: Subject, scopes: Scopes)

trait ConsentStore[F[_]] {

  def grant(record: ConsentRecord): F[Unit]

  def revoke(clientId: ClientId, subject: Subject): F[Unit]

  def decide(clientId: ClientId, subject: Subject, scopes: Scopes): F[Boolean]
}
