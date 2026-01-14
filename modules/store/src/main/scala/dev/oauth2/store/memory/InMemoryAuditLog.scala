package dev.oauth2.store.memory

import cats.effect.kernel.Ref
import cats.syntax.functor._

import dev.oauth2.store.AuditEvent
import dev.oauth2.store.AuditLog

final class InMemoryAuditLog[F[_]] private (state: Ref[F, Vector[AuditEvent]]) extends AuditLog[F] {

  def record(event: AuditEvent): F[Unit] = state.update(_ :+ event)

  def events: F[Vector[AuditEvent]] = state.get
}

object InMemoryAuditLog {

  def create[F[_]: cats.effect.Sync]: F[InMemoryAuditLog[F]] =
    Ref.of[F, Vector[AuditEvent]](Vector.empty).map(state => new InMemoryAuditLog(state))
}
