package kots.oauth2.server

import cats.Functor
import cats.effect.kernel.Ref
import cats.syntax.functor._

import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Subject

final case class SessionId private (value: String)

object SessionId {

  def from(raw: String): Either[ParseFailure, SessionId] =
    Either.cond(
      raw.nonEmpty && raw.forall(character => character.toInt > 32 && character.toInt < 127),
      new SessionId(raw),
      ParseFailure("SessionId", "not printable")
    )
}

trait Login[F[_]] {

  def subject(session: Option[SessionId]): F[Option[Subject]]
}

final class SessionLogin[F[_]: Functor] private (state: Ref[F, Map[SessionId, Subject]]) extends Login[F] {

  def subject(session: Option[SessionId]): F[Option[Subject]] =
    state.get.map(sessions => session.flatMap(sessions.get))

  def login(id: SessionId, value: Subject): F[Unit] = state.update(_ + (id -> value))

  def logout(id: SessionId): F[Unit] = state.update(_ - id)
}

object SessionLogin {

  def create[F[_]: cats.effect.Sync]: F[SessionLogin[F]] =
    Ref.of[F, Map[SessionId, Subject]](Map.empty).map(state => new SessionLogin(state))
}
