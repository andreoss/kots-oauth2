package kots.oauth2.core

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

sealed abstract class IntrospectionResponse(val active: Boolean)

object IntrospectionResponse {

  val ActiveFlag: String = "active"

  case object Inactive extends IntrospectionResponse(false)

  final case class Active(
      kind: TokenTypeHint,
      scopes: Scopes,
      clientId: ClientId,
      username: Subject,
      issuedAt: Instant,
      expiresAt: Instant,
      notBefore: Instant
  ) extends IntrospectionResponse(true)

  object Active {

    val AccessTokenType: String = "Bearer"
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
