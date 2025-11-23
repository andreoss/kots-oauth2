package dev.oauth2.core

import cats.syntax.either._

final case class ClientId private (value: String)

object ClientId {
  def from(raw: String): Either[ParseFailure, ClientId] =
    Text.printable("ClientId", raw).map(new ClientId(_))
}

final case class Subject private (value: String)

object Subject {
  def from(raw: String): Either[ParseFailure, Subject] =
    Text.printable("Subject", raw).map(new Subject(_))
}

final case class GrantId private (value: String)

object GrantId {
  def from(raw: String): Either[ParseFailure, GrantId] =
    Text.printable("GrantId", raw).map(new GrantId(_))
}

final case class KeyId private (value: String)

object KeyId {
  def from(raw: String): Either[ParseFailure, KeyId] =
    Text.printable("KeyId", raw).map(new KeyId(_))
}

final case class State private (value: String)

object State {
  def from(raw: String): Either[ParseFailure, State] =
    Text.printable("State", raw).map(new State(_))
}

final case class Issuer private (value: String)

object Issuer {
  def from(raw: String): Either[ParseFailure, Issuer] =
    for {
      uri <- Either.catchNonFatal(new java.net.URI(raw)).leftMap(_ => ParseFailure("Issuer", "not a uri"))
      _ <- Either.cond(uri.getScheme == "https", (), ParseFailure("Issuer", "not https"))
      _ <- Either.cond(uri.getQuery == null, (), ParseFailure("Issuer", "has a query"))
      _ <- Either.cond(uri.getFragment == null, (), ParseFailure("Issuer", "has a fragment"))
    } yield new Issuer(raw)
}
