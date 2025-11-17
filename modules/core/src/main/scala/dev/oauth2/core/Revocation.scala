package dev.oauth2.core

import cats.data.ValidatedNec
import cats.syntax.all._

sealed abstract class TokenTypeHint(val value: String)

object TokenTypeHint {
  case object AccessToken extends TokenTypeHint("access_token")
  case object RefreshToken extends TokenTypeHint("refresh_token")

  val all: List[TokenTypeHint] = List(AccessToken, RefreshToken)

  def from(raw: String): Either[ParseFailure, TokenTypeHint] =
    all.find(_.value == raw).toRight(ParseFailure("TokenTypeHint", "not access_token or refresh_token"))
}

final case class RevocationToken private (value: String)

object RevocationToken {

  def from(raw: String): Either[ParseFailure, RevocationToken] =
    Text.printable("RevocationToken", raw).map(new RevocationToken(_))

  def asAccessToken(token: RevocationToken): Option[AccessToken] =
    AccessToken.from(token.value).toOption

  def asRefreshToken(token: RevocationToken): Option[RefreshToken] =
    RefreshToken.from(token.value).toOption
}

final case class RevocationRequest(token: RevocationToken, hint: Option[TokenTypeHint])

object RevocationRequest {

  def from(params: Map[String, String]): ValidatedNec[OAuth2Error, RevocationRequest] =
    (
      Params.field(params, "token")(RevocationToken.from),
      Params.fieldOpt(params, "token_type_hint")(TokenTypeHint.from)
    ).mapN(RevocationRequest.apply)
}
