package dev.oauth2.server

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.ClientAuthInput
import dev.oauth2.core.ClientId
import dev.oauth2.core.IntrospectionRequest
import dev.oauth2.core.IntrospectionResponse
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.RevocationToken
import dev.oauth2.core.TokenTypeHint
import dev.oauth2.http.IntrospectionLogic
import dev.oauth2.store.Client
import dev.oauth2.store.GrantStore
import dev.oauth2.store.TokenRecord
import dev.oauth2.store.TokenStore

final class IntrospectionEndpoint[F[_]: Monad](
    authentication: ClientAuthentication[F],
    tokens: TokenStore[F],
    grants: GrantStore[F],
    audit: Option[dev.oauth2.store.AuditLog[F]] = None
) extends IntrospectionLogic[F] {

  private val auditLog: dev.oauth2.store.AuditLog[F] =
    audit.getOrElse(dev.oauth2.store.AuditLog.noop[F])

  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, IntrospectionResponse]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(input) =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => Monad[F].pure(Left(error))
          case Right(client) => introspect(parameters, client)
        }
    }

  private def introspect(
      parameters: Map[String, String],
      client: Client
  ): F[Either[OAuth2Error, IntrospectionResponse]] =
    IntrospectionRequest.from(parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(request) =>
        find(request, client.id)
          .flatMap(found => found.fold(Monad[F].pure(IntrospectionResponse.inactive))(answer))
          .flatMap(response =>
            auditLog
              .record(dev.oauth2.store.AuditEvent.Introspected(client.id, response.active))
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
      case None =>
        byRefresh(request.token, clientId).flatMap {
          case Some(record) => Monad[F].pure(Some(record))
          case None         => byAccess(request.token, clientId)
        }
    }

  private def byAccess(
      token: RevocationToken,
      clientId: ClientId
  ): F[Option[(TokenTypeHint, TokenRecord)]] =
    RevocationToken
      .asAccessToken(token)
      .fold(Monad[F].pure(Option.empty[TokenRecord]))(tokens.findByAccess)
      .map(owned(_, clientId).map(record => (TokenTypeHint.AccessToken: TokenTypeHint, record)))

  private def byRefresh(
      token: RevocationToken,
      clientId: ClientId
  ): F[Option[(TokenTypeHint, TokenRecord)]] =
    RevocationToken
      .asRefreshToken(token)
      .fold(Monad[F].pure(Option.empty[TokenRecord]))(tokens.findByRefresh)
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
      record.issuedAt
    )

  private def expiry(kind: TokenTypeHint, record: TokenRecord): java.time.Instant =
    kind match {
      case TokenTypeHint.AccessToken  => record.accessExpiresAt
      case TokenTypeHint.RefreshToken => record.refreshExpiresAt.getOrElse(record.accessExpiresAt)
    }
}
