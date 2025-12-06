package dev.oauth2.core

import cats.syntax.either._

final case class RedirectUri private (value: String)

object RedirectUri {
  private val LoopbackHosts: Set[String] = Set("127.0.0.1", "[::1]", "localhost")

  def from(raw: String): Either[ParseFailure, RedirectUri] =
    for {
      uri <- Either
        .catchNonFatal(new java.net.URI(raw))
        .leftMap(_ => ParseFailure("RedirectUri", "not a uri"))
      _ <- Either.cond(!raw.contains('*'), (), ParseFailure("RedirectUri", "has a wildcard"))
      _ <- Either.cond(uri.getFragment == null, (), ParseFailure("RedirectUri", "has a fragment"))
      _ <- Either.cond(uri.isAbsolute, (), ParseFailure("RedirectUri", "not absolute"))
      _ <- Either.cond(uri.getRawUserInfo == null, (), ParseFailure("RedirectUri", "has userinfo"))
      _ <- scheme(uri)
    } yield new RedirectUri(raw)

  def exactMatch(registered: Set[RedirectUri], candidate: RedirectUri): Boolean =
    registered.contains(candidate)

  def matches(registered: Set[RedirectUri], candidate: RedirectUri): Boolean =
    exactMatch(registered, candidate) || registered.exists { r =>
      isLoopback(r) && isLoopback(candidate) && sameIgnoringPort(r, candidate)
    }

  def isLoopback(uri: RedirectUri): Boolean =
    parse(uri).exists(u => LoopbackHosts.contains(String.valueOf(u.getHost)))

  def isNativeScheme(uri: RedirectUri): Boolean =
    parse(uri).exists(u => {
      val scheme = u.getScheme
      scheme != "http" && scheme != "https"
    })

  private def parse(uri: RedirectUri): Option[java.net.URI] =
    Either.catchNonFatal(new java.net.URI(uri.value)).toOption

  private def scheme(uri: java.net.URI): Either[ParseFailure, Unit] = {
    val name = uri.getScheme
    if (name == "https") Either.cond(uri.getHost != null, (), ParseFailure("RedirectUri", "has no host"))
    else if (name == "http")
      Either.cond(
        LoopbackHosts.contains(String.valueOf(uri.getHost)),
        (),
        ParseFailure("RedirectUri", "not a loopback host")
      )
    else if (isNative(name)) Right(())
    else Left(ParseFailure("RedirectUri", "unsupported scheme"))
  }

  private def isNative(name: String): Boolean =
    name != null && name.nonEmpty && name.head.isLetter &&
      name.forall(c => c.isLetterOrDigit || c == '.' || c == '+' || c == '-') &&
      name.contains('.')

  private def sameIgnoringPort(a: RedirectUri, b: RedirectUri): Boolean =
    (for {
      x <- parse(a)
      y <- parse(b)
    } yield x.getScheme == y.getScheme && x.getHost == y.getHost && x.getPath == y.getPath && x.getQuery == y.getQuery)
      .getOrElse(false)
}

final case class EndpointUri private (value: String)

object EndpointUri {
  def from(raw: String): Either[ParseFailure, EndpointUri] =
    Text.absolute("EndpointUri", raw).map(new EndpointUri(_))
}

final case class ResourceIndicator private (value: String)

object ResourceIndicator {
  def from(raw: String): Either[ParseFailure, ResourceIndicator] =
    Text.absolute("ResourceIndicator", raw).map(new ResourceIndicator(_))
}

final case class RequestUri private (value: String)

object RequestUri {

  val Prefix: String = "urn:ietf:params:oauth:request_uri:"

  def from(raw: String): Either[ParseFailure, RequestUri] =
    Text.printable("RequestUri", raw).flatMap { value =>
      if (value.startsWith(Prefix) && value.length > Prefix.length) Right(new RequestUri(value))
      else Left(ParseFailure("RequestUri", "not a pushed request uri"))
    }
}
