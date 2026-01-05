package dev.oauth2.core

sealed abstract class OAuth2Error(val code: String, val status: Int) {
  def description: Option[String]
  def errorUri: Option[String]

  final def body: Map[String, String] =
    Map("error" -> code) ++
      description.map("error_description" -> _) ++
      errorUri.map("error_uri" -> _)

  final def challenge: Option[String] = this match {
    case _: OAuth2Error.InvalidClient => Some(OAuth2Error.BasicChallenge)
    case _                            => None
  }
}

object OAuth2Error {
  final case class InvalidRequest(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("invalid_request", 400)

  final case class InvalidClient(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("invalid_client", 401)

  final case class InvalidGrant(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("invalid_grant", 400)

  final case class UnauthorizedClient(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("unauthorized_client", 400)

  final case class UnsupportedGrantType(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("unsupported_grant_type", 400)

  final case class InvalidScope(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("invalid_scope", 400)

  final case class AccessDenied(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("access_denied", 403)

  final case class UnsupportedResponseType(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("unsupported_response_type", 400)

  final case class ServerError(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("server_error", 500)

  final case class TemporarilyUnavailable(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("temporarily_unavailable", 503)

  val BasicChallenge: String = """Basic realm="oauth2""""

  val knownCodes: Set[String] = Set(
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "access_denied",
    "unsupported_response_type",
    "server_error",
    "temporarily_unavailable"
  )

  val knownStatuses: Set[Int] = Set(400, 401, 403, 500, 503)

  def fromParseFailure(failure: ParseFailure): InvalidRequest =
    InvalidRequest(Some(s"${failure.typeName}: ${failure.reason}"))

  def fromWire(status: Int, body: Map[String, String]): Either[ParseFailure, OAuth2Error] =
    for {
      code <- body.get("error").toRight(ParseFailure("OAuth2Error", "no error code"))
      error <- fromCode(code, body)
      _ <- Either.cond(
        error.status == status,
        error,
        ParseFailure("OAuth2Error", s"$status is not the status of ${error.code}")
      )
    } yield error

  private def fromCode(code: String, body: Map[String, String]): Either[ParseFailure, OAuth2Error] = {
    val description = body.get("error_description")
    val errorUri = body.get("error_uri")
    code match {
      case "invalid_request"           => Right(InvalidRequest(description, errorUri))
      case "invalid_client"            => Right(InvalidClient(description, errorUri))
      case "invalid_grant"             => Right(InvalidGrant(description, errorUri))
      case "unauthorized_client"       => Right(UnauthorizedClient(description, errorUri))
      case "unsupported_grant_type"    => Right(UnsupportedGrantType(description, errorUri))
      case "invalid_scope"             => Right(InvalidScope(description, errorUri))
      case "access_denied"             => Right(AccessDenied(description, errorUri))
      case "unsupported_response_type" => Right(UnsupportedResponseType(description, errorUri))
      case "server_error"              => Right(ServerError(description, errorUri))
      case "temporarily_unavailable"   => Right(TemporarilyUnavailable(description, errorUri))
      case other => Left(ParseFailure("OAuth2Error", s"unknown error code: $other"))
    }
  }
}
