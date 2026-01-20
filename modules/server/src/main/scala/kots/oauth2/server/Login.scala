package kots.oauth2.server

import cats.effect.kernel.Ref
import cats.syntax.functor._

import kots.oauth2.core.Subject

trait Login[F[_]] {

  def subject: F[Option[Subject]]
}

final class SessionLogin[F[_]] private (state: Ref[F, Option[Subject]]) extends Login[F] {

  def subject: F[Option[Subject]] = state.get

  def login(value: Subject): F[Unit] = state.set(Some(value))

  def logout: F[Unit] = state.set(None)
}

object SessionLogin {

  def create[F[_]: cats.effect.Sync]: F[SessionLogin[F]] =
    Ref.of[F, Option[Subject]](None).map(state => new SessionLogin(state))
}
