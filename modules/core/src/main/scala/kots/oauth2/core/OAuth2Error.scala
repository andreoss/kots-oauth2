package kots.oauth2.core

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

  final case class InvalidAuthorizationDetails(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("invalid_authorization_details", 400)

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

  final case class AuthorizationPending(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("authorization_pending", 400)

  final case class SlowDown(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("slow_down", 400)

  final case class ExpiredToken(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("expired_token", 400)

  final case class InvalidClientMetadata(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("invalid_client_metadata", 400)

  final case class InvalidRedirectUri(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("invalid_redirect_uri", 400)

  final case class InvalidDpopProof(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("invalid_dpop_proof", 400)

  final case class UseDpopNonce(
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("use_dpop_nonce", 400)

  final case class RateLimited(
      retryAfter: Long,
      description: Option[String] = None,
      errorUri: Option[String] = None
  ) extends OAuth2Error("temporarily_unavailable", 429)

  val BasicRealm: String = "oauth2"

  val BasicChallenge: String = s"""Basic realm="$BasicRealm""""

  val knownCodes: Set[String] = Set(
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_authorization_details",
    "access_denied",
    "unsupported_response_type",
    "server_error",
    "temporarily_unavailable",
    "authorization_pending",
    "slow_down",
    "expired_token",
    "invalid_client_metadata",
    "invalid_redirect_uri",
    "invalid_dpop_proof",
    "use_dpop_nonce"
  )

  val knownStatuses: Set[Int] = Set(400, 401, 403, 429, 500, 503)

  val RateLimitStatus: Int = 429

  def fromParseFailure(failure: ParseFailure): InvalidRequest =
    InvalidRequest(Some(s"${failure.typeName}: ${failure.reason}"))

  def fromWire(status: Int, body: Map[String, String]): Either[ParseFailure, OAuth2Error] =
    for {
      code <- body.get("error").toRight(ParseFailure("OAuth2Error", "no error code"))
      parsed <- fromCode(code, body)
      error = parsed match {
        case unavailable: TemporarilyUnavailable if status == RateLimitStatus =>
          RateLimited(0L, unavailable.description, unavailable.errorUri)
        case other => other
      }
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
      case "authorization_pending"     => Right(AuthorizationPending(description, errorUri))
      case "slow_down"                 => Right(SlowDown(description, errorUri))
      case "expired_token"             => Right(ExpiredToken(description, errorUri))
      case "invalid_client_metadata"   => Right(InvalidClientMetadata(description, errorUri))
      case "invalid_redirect_uri"      => Right(InvalidRedirectUri(description, errorUri))
      case "invalid_dpop_proof"        => Right(InvalidDpopProof(description, errorUri))
      case "use_dpop_nonce"            => Right(UseDpopNonce(description, errorUri))
      case other                       => Left(ParseFailure("OAuth2Error", s"unknown error code: $other"))
    }
  }
}
