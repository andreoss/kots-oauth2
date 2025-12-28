package kots.oauth2.core

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

final case class Audience private (value: String)

object Audience {
  def from(raw: String): Either[ParseFailure, Audience] =
    Text.printable("Audience", raw).map(new Audience(_))
}

final case class JwtId private (value: String)

object JwtId {
  def from(raw: String): Either[ParseFailure, JwtId] =
    Text.printable("JwtId", raw).map(new JwtId(_))
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

  private val LoopbackHosts: Set[String] = Set("localhost", "127.0.0.1", "[::1]")

  def from(raw: String): Either[ParseFailure, Issuer] =
    for {
      uri <- Either.catchNonFatal(new java.net.URI(raw)).leftMap(_ => ParseFailure("Issuer", "not a uri"))
      _ <- Either.cond(
        uri.getScheme == "https" ||
          (uri.getScheme == "http" && LoopbackHosts.contains(uri.getHost)),
        (),
        ParseFailure("Issuer", "not https")
      )
      _ <- Either.cond(uri.getQuery == null, (), ParseFailure("Issuer", "has a query"))
      _ <- Either.cond(uri.getFragment == null, (), ParseFailure("Issuer", "has a fragment"))
    } yield new Issuer(raw)
}

final case class Acr private (value: String)

object Acr {
  def from(raw: String): Either[ParseFailure, Acr] =
    Text.printable("Acr", raw).map(new Acr(_))
}

final case class KeyThumbprint private (value: String)

object KeyThumbprint {
  def from(raw: String): Either[ParseFailure, KeyThumbprint] =
    Text.printable("KeyThumbprint", raw).map(new KeyThumbprint(_))
}
