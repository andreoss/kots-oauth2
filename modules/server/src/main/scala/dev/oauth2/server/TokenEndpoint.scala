package dev.oauth2.server

import java.time.Duration

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.ClientAuthInput
import dev.oauth2.core.ExchangeTokenType
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.TokenRequest
import dev.oauth2.http.TokenLogic
import dev.oauth2.http.TokenResponse
import dev.oauth2.store.Client
import dev.oauth2.store.IssuedToken

final class TokenEndpoint[F[_]: Monad](
    authentication: ClientAuthentication[F],
    tokens: TokenService[F]
) extends TokenLogic[F] {

  def apply(
      basic: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, TokenResponse]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(input) =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => Monad[F].pure(Left(error))
          case Right(client) => grant(parameters, client)
        }
    }

  private def grant(
      parameters: Map[String, String],
      client: Client
  ): F[Either[OAuth2Error, TokenResponse]] =
    TokenRequest.from(parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(request) =>
        request match {
          case code: TokenRequest.Code       => tokens.authorizationCode(code, client).map(_.map(TokenEndpoint.render))
          case refresh: TokenRequest.Refresh => tokens.refresh(refresh, client).map(_.map(TokenEndpoint.render))
          case credentials: TokenRequest.ClientCredentials =>
            tokens.clientCredentials(credentials, client).map(_.map(TokenEndpoint.render))
          case device: TokenRequest.Device =>
            tokens.deviceCode(device, client).map(_.map(TokenEndpoint.render))
          case exchange: TokenRequest.Exchange =>
            tokens
              .exchange(exchange, client)
              .map(_.map(issued => TokenEndpoint.render(issued).copy(issuedTokenType = Some(ExchangeTokenType.AccessToken))))
        }
    }
}

object TokenEndpoint {

  def render(issued: IssuedToken): TokenResponse =
    TokenResponse(
      accessToken = issued.accessToken,
      expiresIn = Duration.between(issued.record.issuedAt, issued.record.accessExpiresAt).getSeconds,
      scope = issued.record.scopes,
      refreshToken = issued.refreshToken
    )
}
