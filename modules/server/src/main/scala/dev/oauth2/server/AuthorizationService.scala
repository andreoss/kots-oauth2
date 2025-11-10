package dev.oauth2.server

import cats.Monad
import cats.data.ValidatedNec
import cats.syntax.all._

import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.AuthorizationRequest
import dev.oauth2.core.ClientId
import dev.oauth2.core.Clock
import dev.oauth2.core.CodeChallengeMethod
import dev.oauth2.core.Entropy
import dev.oauth2.core.Lifetime
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TokenType
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.CodeStore

final class AuthorizationService[F[_]: Monad](
    codes: CodeStore[F],
    clock: Clock[F],
    entropy: Entropy[F],
    policy: LifetimePolicy
) {

  def issue(
      request: AuthorizationRequest,
      client: Client,
      subject: Subject,
      details: AuthorizationDetails
  ): F[Either[OAuth2Error, AuthorizationCode]] =
    validate(request, client).fold(
      errors => Monad[F].pure(Left(errors.head)),
      { case (redirectUri, scopes, pkce) => mint(request.clientId, redirectUri, subject, scopes, details, pkce) }
    )

  private def validate(
      request: AuthorizationRequest,
      client: Client
  ): ValidatedNec[OAuth2Error, (RedirectUri, Scopes, Pkce)] =
    (redirect(client, request.redirectUri), scopes(client, request.scope), challenge(request.pkce)).tupled

  private def redirect(
      client: Client,
      requested: Option[RedirectUri]
  ): ValidatedNec[OAuth2Error, RedirectUri] =
    (requested, client.redirectUris.toList) match {
      case (Some(uri), _) if client.allowsRedirect(uri) => uri.validNec
      case (Some(_), _) =>
        OAuth2Error.InvalidRequest(Some("redirect_uri is not registered")).invalidNec
      case (None, single :: Nil) => single.validNec
      case (None, _) => OAuth2Error.InvalidRequest(Some("redirect_uri is required")).invalidNec
    }

  private def scopes(client: Client, requested: Scopes): ValidatedNec[OAuth2Error, Scopes] =
    Either
      .cond(client.allowsScopes(requested), requested, OAuth2Error.InvalidScope(): OAuth2Error)
      .toValidatedNec

  private def challenge(requested: Option[Pkce]): ValidatedNec[OAuth2Error, Pkce] =
    requested match {
      case Some(pkce) if pkce.method == CodeChallengeMethod.S256 => pkce.validNec
      case Some(_) =>
        OAuth2Error.InvalidRequest(Some("only S256 code_challenge_method is supported")).invalidNec
      case None => OAuth2Error.InvalidRequest(Some("code_challenge is required")).invalidNec
    }

  private def mint(
      clientId: ClientId,
      redirectUri: RedirectUri,
      subject: Subject,
      scopes: Scopes,
      details: AuthorizationDetails,
      pkce: Pkce
  ): F[Either[OAuth2Error, AuthorizationCode]] =
    for {
      now <- clock.instant
      raw <- entropy.bytes(AuthorizationService.CodeEntropyBytes)
      parsed = AuthorizationCode
        .from(Entropy.hex(raw))
        .leftMap(failure => OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}")): OAuth2Error)
      issued <- parsed.fold(
        error => Monad[F].pure(Left(error)),
        code =>
          codes
            .save(
              CodeRecord(
                code = code,
                clientId = clientId,
                redirectUri = redirectUri,
                subject = subject,
                scopes = scopes,
                details = details,
                pkce = Some(pkce),
                expiresAt = Lifetime.expiresAt(now, LifetimePolicy.of(policy, TokenType.AuthorizationCode))
              )
            )
            .as(Right(code))
      )
    } yield issued
}

object AuthorizationService {
  val CodeEntropyBytes: Int = 32
}
