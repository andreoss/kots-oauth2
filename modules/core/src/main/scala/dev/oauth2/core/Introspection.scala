package dev.oauth2.core

import java.time.Instant

import cats.data.ValidatedNec
import cats.syntax.all._

final case class IntrospectionRequest(token: RevocationToken, hint: Option[TokenTypeHint])

object IntrospectionRequest {

  def from(params: Map[String, String]): ValidatedNec[OAuth2Error, IntrospectionRequest] =
    (
      Params.field(params, "token")(RevocationToken.from),
      Params.fieldOpt(params, "token_type_hint")(TokenTypeHint.from)
    ).mapN(IntrospectionRequest.apply)
}

sealed abstract class IntrospectionResponse(val active: Boolean) {
  def body: Map[String, String]
}

object IntrospectionResponse {

  val ActiveFlag: String = "active"

  case object Inactive extends IntrospectionResponse(false) {
    def body: Map[String, String] = Map(ActiveFlag -> "false")
  }

  final case class Active(
      kind: TokenTypeHint,
      scopes: Scopes,
      clientId: ClientId,
      username: Subject,
      issuedAt: Instant,
      expiresAt: Instant,
      notBefore: Instant
  ) extends IntrospectionResponse(true) {

    def body: Map[String, String] =
      Map(
        ActiveFlag -> "true",
        "client_id" -> Wire[ClientId].encode(clientId),
        "username" -> Wire[Subject].encode(username),
        "token_type" -> Active.tokenType(kind),
        "exp" -> expiresAt.getEpochSecond.toString,
        "iat" -> issuedAt.getEpochSecond.toString,
        "nbf" -> notBefore.getEpochSecond.toString,
        "sub" -> Wire[Subject].encode(username)
      ) ++ (if (scopes.value.isEmpty) Map.empty[String, String]
            else Map("scope" -> Wire[Scopes].encode(scopes)))
  }

  object Active {

    def tokenType(kind: TokenTypeHint): String = kind match {
      case TokenTypeHint.AccessToken  => "Bearer"
      case TokenTypeHint.RefreshToken => "refresh_token"
    }
  }

  def inactive: IntrospectionResponse = Inactive

  def active(
      kind: TokenTypeHint,
      scopes: Scopes,
      clientId: ClientId,
      username: Subject,
      issuedAt: Instant,
      expiresAt: Instant,
      notBefore: Instant
  ): IntrospectionResponse =
    Active(kind, scopes, clientId, username, issuedAt, expiresAt, notBefore)
}
