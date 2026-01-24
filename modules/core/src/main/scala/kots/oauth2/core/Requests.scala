package kots.oauth2.core

import cats.data.ValidatedNec
import cats.syntax.all._

sealed abstract class ResponseType(val value: String)

object ResponseType {
  case object Code extends ResponseType("code")

  val all: List[ResponseType] = List(Code)

  def from(raw: String): Either[ParseFailure, ResponseType] =
    all.find(_.value == raw).toRight(ParseFailure("ResponseType", "not code"))
}

sealed abstract class GrantType(val value: String) {
  def actsForAnOwner: Boolean = this != GrantType.ClientCredentials
}

object GrantType {
  case object AuthorizationCode extends GrantType("authorization_code")
  case object RefreshToken extends GrantType("refresh_token")
  case object ClientCredentials extends GrantType("client_credentials")
  case object DeviceCode extends GrantType("urn:ietf:params:oauth:grant-type:device_code")
  case object TokenExchange extends GrantType("urn:ietf:params:oauth:grant-type:token-exchange")
  case object IdJag extends GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer")

  val all: List[GrantType] =
    List(AuthorizationCode, RefreshToken, ClientCredentials, DeviceCode, TokenExchange, IdJag)

  def from(raw: String): Either[ParseFailure, GrantType] =
    all.find(_.value == raw).toRight(ParseFailure("GrantType", "not a registered grant type"))
}

final case class AuthorizationRequest(
    responseType: ResponseType,
    clientId: ClientId,
    redirectUri: Option[RedirectUri],
    scope: Scopes,
    state: State,
    pkce: Option[Pkce],
    resource: Option[ResourceIndicator] = None
)

object AuthorizationRequest {

  def from(params: Map[String, String]): ValidatedNec[OAuth2Error, AuthorizationRequest] =
    (
      Params.required(params, "response_type")(raw =>
        ResponseType.from(raw).leftMap(_ => OAuth2Error.UnsupportedResponseType(): OAuth2Error)
      ),
      Params.field(params, "client_id")(ClientId.from),
      Params.fieldOpt(params, "redirect_uri")(RedirectUri.from),
      Params.fieldOpt(params, "scope")(Scopes.parse),
      Params.field(params, "state")(State.from),
      (
        Params.fieldOpt(params, "code_challenge")(CodeChallenge.from),
        Params.fieldOpt(params, "code_challenge_method")(CodeChallengeMethod.from)
      ).tupled.andThen { case (challenge, method) => pkce(challenge, method) },
      Params.fieldOpt(params, "resource")(ResourceIndicator.from)
    ).mapN { case (responseType, clientId, redirectUri, scope, state, pkce, resource) =>
      AuthorizationRequest(
        responseType,
        clientId,
        redirectUri,
        scope.getOrElse(Scopes.empty),
        state,
        pkce,
        resource
      )
    }

  private def pkce(
      challenge: Option[CodeChallenge],
      method: Option[CodeChallengeMethod]
  ): ValidatedNec[OAuth2Error, Option[Pkce]] =
    (challenge, method) match {
      case (Some(c), m)    => Some(Pkce(c, m.getOrElse(CodeChallengeMethod.Plain))).validNec
      case (None, Some(_)) =>
        OAuth2Error.InvalidRequest(Some("code_challenge_method without code_challenge")).invalidNec
      case (None, None) => None.validNec
    }
}

sealed abstract class TokenRequest

object TokenRequest {
  final case class Code(
      code: AuthorizationCode,
      redirectUri: Option[RedirectUri],
      verifier: CodeVerifier,
      clientId: ClientId,
      resource: Option[ResourceIndicator] = None
  ) extends TokenRequest

  final case class Refresh(
      refreshToken: RefreshToken,
      scope: Option[Scopes],
      clientId: ClientId,
      resource: Option[ResourceIndicator] = None
  ) extends TokenRequest

  final case class ClientCredentials(
      scope: Option[Scopes],
      clientId: ClientId,
      resource: Option[ResourceIndicator] = None
  ) extends TokenRequest

  final case class Device(
      deviceCode: DeviceCode,
      clientId: ClientId,
      resource: Option[ResourceIndicator] = None
  ) extends TokenRequest

  final case class Exchange(
      subjectToken: AccessToken,
      actorToken: Option[AccessToken],
      audience: Option[Audience],
      resource: Option[ResourceIndicator],
      scope: Option[Scopes],
      clientId: ClientId
  ) extends TokenRequest

  final case class IdJag(
      assertion: IdentityAssertion,
      scope: Option[Scopes],
      resource: Option[ResourceIndicator],
      clientId: ClientId,
      details: Option[AuthorizationDetailsDocument] = None
  ) extends TokenRequest

  def from(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    Params
      .required(params, "grant_type")(raw =>
        GrantType.from(raw).leftMap(_ => OAuth2Error.UnsupportedGrantType(): OAuth2Error)
      )
      .andThen {
        case GrantType.AuthorizationCode => authorizationCode(params)
        case GrantType.RefreshToken      => refreshToken(params)
        case GrantType.ClientCredentials => clientCredentials(params)
        case GrantType.DeviceCode        => device(params)
        case GrantType.TokenExchange     => exchange(params)
        case GrantType.IdJag             => idJag(params)
      }

  private def authorizationCode(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    (
      Params.field(params, "code")(AuthorizationCode.from),
      Params.fieldOpt(params, "redirect_uri")(RedirectUri.from),
      Params.field(params, "code_verifier")(CodeVerifier.from),
      Params.field(params, "client_id")(ClientId.from),
      Params.fieldOpt(params, "resource")(ResourceIndicator.from)
    ).mapN(Code.apply)

  private def refreshToken(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    (
      Params.field(params, "refresh_token")(RefreshToken.from),
      Params.fieldOpt(params, "scope")(Scopes.parse),
      Params.field(params, "client_id")(ClientId.from),
      Params.fieldOpt(params, "resource")(ResourceIndicator.from)
    ).mapN(Refresh.apply)

  private def clientCredentials(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    (
      Params.fieldOpt(params, "scope")(Scopes.parse),
      Params.field(params, "client_id")(ClientId.from),
      Params.fieldOpt(params, "resource")(ResourceIndicator.from)
    ).mapN(ClientCredentials.apply)

  private def device(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    (
      Params.field(params, "device_code")(DeviceCode.from),
      Params.field(params, "client_id")(ClientId.from),
      Params.fieldOpt(params, "resource")(ResourceIndicator.from)
    ).mapN(Device.apply)

  private def exchange(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    (
      (
        Params.field(params, "subject_token")(AccessToken.from),
        Params.field(params, "subject_token_type")(ExchangeTokenType.from)
      ).mapN((token, _) => token),
      (
        Params.fieldOpt(params, "actor_token")(AccessToken.from),
        Params.fieldOpt(params, "actor_token_type")(ExchangeTokenType.from)
      ).tupled.andThen { case (token, kind) => actor(token, kind) },
      Params.fieldOpt(params, "requested_token_type")(ExchangeTokenType.from),
      Params.fieldOpt(params, "audience")(Audience.from),
      Params.fieldOpt(params, "resource")(ResourceIndicator.from),
      Params.fieldOpt(params, "scope")(Scopes.parse),
      Params.field(params, "client_id")(ClientId.from)
    ).mapN { case (subjectToken, actorToken, _, audience, resource, scope, clientId) =>
      Exchange(subjectToken, actorToken, audience, resource, scope, clientId)
    }

  private def idJag(params: Map[String, String]): ValidatedNec[OAuth2Error, TokenRequest] =
    (
      Params.field(params, "assertion")(IdentityAssertion.from),
      Params.fieldOpt(params, "scope")(Scopes.parse),
      Params.fieldOpt(params, "resource")(ResourceIndicator.from),
      Params.field(params, "client_id")(ClientId.from),
      Params.fieldOpt(params, "authorization_details")(AuthorizationDetailsDocument.from)
    ).mapN(IdJag.apply)

  private def actor(
      token: Option[AccessToken],
      kind: Option[ExchangeTokenType]
  ): ValidatedNec[OAuth2Error, Option[AccessToken]] =
    (token, kind) match {
      case (Some(value), Some(_)) => value.some.validNec
      case (None, None)           => none[AccessToken].validNec
      case _                      =>
        (OAuth2Error.InvalidRequest(
          Some("actor_token and actor_token_type go together")
        ): OAuth2Error).invalidNec
    }
}

sealed abstract class ExchangeTokenType(val value: String)

object ExchangeTokenType {
  case object AccessToken extends ExchangeTokenType("urn:ietf:params:oauth:token-type:access_token")

  val all: List[ExchangeTokenType] = List(AccessToken)

  def from(raw: String): Either[ParseFailure, ExchangeTokenType] =
    all.find(_.value == raw).toRight(ParseFailure("ExchangeTokenType", "not a supported token type"))
}

final case class AuthorizationDetailsDocument private (value: String)

object AuthorizationDetailsDocument {
  def from(raw: String): Either[ParseFailure, AuthorizationDetailsDocument] = {
    val trimmed = raw.trim
    Either.cond(
      trimmed.startsWith("[") && trimmed.endsWith("]"),
      new AuthorizationDetailsDocument(trimmed),
      ParseFailure("AuthorizationDetailsDocument", "not a json array")
    )
  }
}

final case class IdentityAssertion private (value: String)

object IdentityAssertion {
  def from(raw: String): Either[ParseFailure, IdentityAssertion] = {
    val parts = raw.split('.')
    Either.cond(
      parts.length == 3 && parts.forall(_.nonEmpty),
      new IdentityAssertion(raw),
      ParseFailure("IdentityAssertion", "not a compact jws")
    )
  }
}

final case class DeviceAuthorizationRequest(
    scope: Option[Scopes],
    clientId: ClientId,
    resource: Option[ResourceIndicator] = None
)

object DeviceAuthorizationRequest {

  def from(params: Map[String, String]): ValidatedNec[OAuth2Error, DeviceAuthorizationRequest] =
    (
      Params.fieldOpt(params, "scope")(Scopes.parse),
      Params.field(params, "client_id")(ClientId.from),
      Params.fieldOpt(params, "resource")(ResourceIndicator.from)
    ).mapN(DeviceAuthorizationRequest.apply)
}
