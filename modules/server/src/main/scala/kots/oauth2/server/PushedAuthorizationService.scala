package kots.oauth2.server

import cats.Monad
import cats.syntax.all._

import kots.oauth2.core.AuthorizationRequest
import kots.oauth2.core.Clock
import kots.oauth2.core.Entropy
import kots.oauth2.core.Lifetime
import kots.oauth2.core.LifetimePolicy
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.RequestUri
import kots.oauth2.core.TokenType
import kots.oauth2.http.PushedAuthorizationResponse
import kots.oauth2.store.Client
import kots.oauth2.store.PushedRequest
import kots.oauth2.store.PushedRequestStore

final class PushedAuthorizationService[F[_]: Monad](
    pushed: PushedRequestStore[F],
    clock: Clock[F],
    entropy: Entropy[F],
    policy: LifetimePolicy
) {

  def push(
      parameters: Map[String, String],
      client: Client
  ): F[Either[OAuth2Error, PushedAuthorizationResponse]] = {
    val stripped = parameters -- PushedAuthorizationService.AuthParameters
    AuthorizationRequest.from(stripped).toEither match {
      case Left(failures)                                  => Monad[F].pure(Left(failures.head))
      case Right(request) if request.clientId != client.id =>
        Monad[F].pure(Left(OAuth2Error.InvalidRequest(Some("client_id does not match")): OAuth2Error))
      case Right(_) =>
        val lifetime = LifetimePolicy.of(policy, TokenType.AuthorizationCode)
        for {
          now <- clock.instant
          raw <- entropy.bytes(PushedAuthorizationService.UriEntropyBytes)
          minted = RequestUri
            .from(RequestUri.Prefix + Entropy.hex(raw))
            .leftMap(failure =>
              OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}")): OAuth2Error
            )
          result <- minted.fold(
            error => Monad[F].pure(Left(error): Either[OAuth2Error, PushedAuthorizationResponse]),
            uri =>
              pushed
                .save(PushedRequest(uri, client.id, stripped, Lifetime.expiresAt(now, lifetime)))
                .as(
                  Right(PushedAuthorizationResponse(uri, lifetime.seconds)): Either[
                    OAuth2Error,
                    PushedAuthorizationResponse
                  ]
                )
          )
        } yield result
    }
  }
}

object PushedAuthorizationService {

  val UriEntropyBytes: Int = 32

  val AuthParameters: Set[String] = Set("client_secret", "client_assertion", "client_assertion_type")
}
