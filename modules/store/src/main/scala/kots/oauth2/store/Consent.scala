package kots.oauth2.store

import kots.oauth2.core.ClientId
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject

final case class ConsentRecord(clientId: ClientId, subject: Subject, scopes: Scopes)

trait ConsentStore[F[_]] {

  def grant(record: ConsentRecord): F[Unit]

  def revoke(clientId: ClientId, subject: Subject): F[Unit]

  def decide(clientId: ClientId, subject: Subject, scopes: Scopes): F[Boolean]
}
