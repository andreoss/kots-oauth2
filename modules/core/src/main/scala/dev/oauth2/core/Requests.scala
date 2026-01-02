package dev.oauth2.core

import cats.data.ValidatedNec
import cats.syntax.all._

sealed abstract class ResponseType(val value: String)

object ResponseType {
  case object Code extends ResponseType("code")

  val all: List[ResponseType] = List(Code)

  def from(raw: String): Either[ParseFailure, ResponseType] =
    all.find(_.value == raw).toRight(ParseFailure("ResponseType", "not code"))
}

sealed abstract class GrantType(val value: String)

object GrantType {
  case object AuthorizationCode extends GrantType("authorization_code")
  case object RefreshToken extends GrantType("refresh_token")
  case object ClientCredentials extends GrantType("client_credentials")

  val all: List[GrantType] = List(AuthorizationCode, RefreshToken, ClientCredentials)

  def from(raw: String): Either[ParseFailure, GrantType] =
    all.find(_.value == raw).toRight(ParseFailure("GrantType", "not a registered grant type"))
}

final case class AuthorizationRequest(
    responseType: ResponseType,
    clientId: ClientId,
    redirectUri: Option[RedirectUri],
    scope: Scopes,
    state: Option[State],
    pkce: Option[Pkce]
)

object AuthorizationRequest {

  def from(params: Map[String, String]): ValidatedNec[OAuth2Error, AuthorizationRequest] =
    (
      Params.required(params, "response_type")(
        raw => ResponseType.from(raw).leftMap(_ => OAuth2Error.UnsupportedResponseType(): OAuth2Error)
      ),
      Params.field(params, "client_id")(ClientId.from),
      Params.fieldOpt(params, "redirect_uri")(RedirectUri.from),
      Params.fieldOpt(params, "scope")(Scopes.parse),
      Params.fieldOpt(params, "state")(State.from),
      (
        Params.fieldOpt(params, "code_challenge")(CodeChallenge.from),
        Params.fieldOpt(params, "code_challenge_method")(CodeChallengeMethod.from)
      ).tupled.andThen { case (challenge, method) => pkce(challenge, method) }
    ).mapN { case (responseType, clientId, redirectUri, scope, state, pkce) =>
      AuthorizationRequest(responseType, clientId, redirectUri, scope.getOrElse(Scopes.empty), state, pkce)
    }

  private def pkce(
      challenge: Option[CodeChallenge],
      method: Option[CodeChallengeMethod]
  ): ValidatedNec[OAuth2Error, Option[Pkce]] =
    (challenge, method) match {
      case (Some(c), m)   => Some(Pkce(c, m.getOrElse(CodeChallengeMethod.Plain))).validNec
      case (None, Some(_)) =>
        OAuth2Error.InvalidRequest(Some("code_challenge_method without code_challenge")).invalidNec
      case (None, None)   => None.validNec
    }
}

sealed abstract class TokenRequest

object TokenRequest {
  final case class Code(
      code: AuthorizationCode,
      redirectUri: Option[RedirectUri],
      verifier: CodeVerifier,
      clientId: ClientId
  ) extends TokenRequest

  def from(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    Params
      .required(params, "grant_type")(
        raw => GrantType.from(raw).leftMap(_ => OAuth2Error.UnsupportedGrantType(): OAuth2Error)
      )
      .andThen {
        case GrantType.AuthorizationCode => authorizationCode(params)
        case other => OAuth2Error.UnsupportedGrantType(Some(s"${other.value} is not supported")).invalidNec
      }

  private def authorizationCode(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    (
      Params.field(params, "code")(AuthorizationCode.from),
      Params.fieldOpt(params, "redirect_uri")(RedirectUri.from),
      Params.field(params, "code_verifier")(CodeVerifier.from),
      Params.field(params, "client_id")(ClientId.from)
    ).mapN(Code.apply)
}
