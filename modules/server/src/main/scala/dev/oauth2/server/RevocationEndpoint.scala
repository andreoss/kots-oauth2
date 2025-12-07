package dev.oauth2.server

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.ClientAuthInput
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.RevocationRequest
import dev.oauth2.http.RevocationLogic
import dev.oauth2.store.AuditEvent
import dev.oauth2.store.AuditLog
import dev.oauth2.store.Client
import dev.oauth2.store.GrantStore
import dev.oauth2.store.TokenStore

final class RevocationEndpoint[F[_]: Monad](
    authentication: ClientAuthentication[F],
    tokens: TokenStore[F],
    grants: GrantStore[F],
    audit: Option[AuditLog[F]] = None
) extends RevocationLogic[F] {

  private val auditLog: AuditLog[F] = audit.getOrElse(AuditLog.noop[F])

  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, Unit]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(input) =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => Monad[F].pure(Left(error))
          case Right(client) => revoke(parameters, client)
        }
    }

  private def revoke(
      parameters: Map[String, String],
      client: Client
  ): F[Either[OAuth2Error, Unit]] =
    RevocationRequest.from(parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(request) =>
        tokens
          .revoke(request.token, request.hint, client.id)
          .flatMap(revoked =>
            revoked.fold(Monad[F].unit)(grant =>
              grants.revoke(grant) >> auditLog.record(AuditEvent.Revoked(client.id, grant))
            )
          )
          .map(Right(_))
    }
}
