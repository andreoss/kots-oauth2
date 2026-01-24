package kots.oauth2.server

import cats.syntax.all._
import cats.Monad

import kots.oauth2.core.ClientAuthInput
import kots.oauth2.core.ClientId
import kots.oauth2.core.IntrospectionRequest
import kots.oauth2.core.IntrospectionResponse
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.RevocationToken
import kots.oauth2.core.TokenTypeHint
import kots.oauth2.http.IntrospectionLogic
import kots.oauth2.store.Client
import kots.oauth2.store.GrantStore
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.TokenStore

final class IntrospectionEndpoint[F[_]: Monad](
    authentication: ClientAuthentication[F],
    tokens: TokenStore[F],
    grants: GrantStore[F],
    audit: Option[kots.oauth2.store.AuditLog[F]] = None
) extends IntrospectionLogic[F] {

  private val auditLog: kots.oauth2.store.AuditLog[F] =
    audit.getOrElse(kots.oauth2.store.AuditLog.noop[F])

  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, IntrospectionResponse]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => failures.head.asLeft.pure[F]
      case Right(input)   =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => error.asLeft.pure[F]
          case Right(client) => introspect(parameters, client)
        }
    }

  private def introspect(
      parameters: Map[String, String],
      client: Client
  ): F[Either[OAuth2Error, IntrospectionResponse]] =
    IntrospectionRequest.from(parameters).toEither match {
      case Left(failures) => failures.head.asLeft.pure[F]
      case Right(request) =>
        find(request, client.id)
          .flatMap(found => found.fold(IntrospectionResponse.inactive.pure[F])(answer))
          .flatMap(response =>
            auditLog
              .record(kots.oauth2.store.AuditEvent.Introspected(client.id, response.active))
              .as(response)
          )
          .map(Right(_))
    }

  private def find(
      request: IntrospectionRequest,
      clientId: ClientId
  ): F[Option[(TokenTypeHint, TokenRecord)]] =
    request.hint match {
      case Some(TokenTypeHint.AccessToken)  => byAccess(request.token, clientId)
      case Some(TokenTypeHint.RefreshToken) => byRefresh(request.token, clientId)
      case None                             =>
        byRefresh(request.token, clientId).flatMap {
          case Some(record) => record.some.pure[F]
          case None         => byAccess(request.token, clientId)
        }
    }

  private def byAccess(
      token: RevocationToken,
      clientId: ClientId
  ): F[Option[(TokenTypeHint, TokenRecord)]] =
    RevocationToken
      .asAccessToken(token)
      .fold(Option.empty[TokenRecord].pure[F])(tokens.findByAccess)
      .map(owned(_, clientId).map(record => (TokenTypeHint.AccessToken: TokenTypeHint, record)))

  private def byRefresh(
      token: RevocationToken,
      clientId: ClientId
  ): F[Option[(TokenTypeHint, TokenRecord)]] =
    RevocationToken
      .asRefreshToken(token)
      .fold(Option.empty[TokenRecord].pure[F])(tokens.findByRefresh)
      .map(owned(_, clientId).map(record => (TokenTypeHint.RefreshToken: TokenTypeHint, record)))

  private def owned(record: Option[TokenRecord], clientId: ClientId): Option[TokenRecord] =
    record.filter(_.clientId == clientId)

  private def answer(found: (TokenTypeHint, TokenRecord)): F[IntrospectionResponse] = {
    val (kind, record) = found
    grants.find(record.grantId).map {
      case Some(grant) if !grant.revoked => IntrospectionEndpoint.render(kind, record)
      case _                             => IntrospectionResponse.inactive
    }
  }
}

object IntrospectionEndpoint {

  def render(kind: TokenTypeHint, record: TokenRecord): IntrospectionResponse =
    IntrospectionResponse.active(
      kind,
      record.scopes,
      record.clientId,
      record.subject,
      record.issuedAt,
      IntrospectionEndpoint.expiry(kind, record),
      record.issuedAt,
      if (record.grant.actsForAnOwner) Some(record.subject) else None
    )

  private def expiry(kind: TokenTypeHint, record: TokenRecord): java.time.Instant =
    kind match {
      case TokenTypeHint.AccessToken  => record.accessExpiresAt
      case TokenTypeHint.RefreshToken => record.refreshExpiresAt.getOrElse(record.accessExpiresAt)
    }
}
