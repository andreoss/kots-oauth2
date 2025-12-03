package dev.oauth2.core

import cats.syntax.either._

private[core] object Text {
  val MaxLength: Int = 512

  val TokenMaxLength: Int = 4096

  def printable(typeName: String, raw: String): Either[ParseFailure, String] =
    bounded(typeName, raw, MaxLength)

  def printableToken(typeName: String, raw: String): Either[ParseFailure, String] =
    bounded(typeName, raw, TokenMaxLength)

  private def bounded(typeName: String, raw: String, limit: Int): Either[ParseFailure, String] =
    if (raw.isEmpty) Left(ParseFailure(typeName, "empty"))
    else if (raw.length > limit) Left(ParseFailure(typeName, "too long"))
    else if (!raw.forall(c => c >= 0x21 && c <= 0x7e)) Left(ParseFailure(typeName, "not printable"))
    else Right(raw)

  def absolute(typeName: String, raw: String): Either[ParseFailure, String] =
    Either
      .catchNonFatal(new java.net.URI(raw))
      .leftMap(_ => ParseFailure(typeName, "not a uri"))
      .flatMap { uri =>
        if (!uri.isAbsolute) Left(ParseFailure(typeName, "not absolute"))
        else if (uri.getFragment != null) Left(ParseFailure(typeName, "has a fragment"))
        else if (isHierarchical(uri) && uri.getHost == null) Left(ParseFailure(typeName, "has no host"))
        else Right(raw)
      }

  private def isHierarchical(uri: java.net.URI): Boolean =
    uri.getScheme == "http" || uri.getScheme == "https"
}
