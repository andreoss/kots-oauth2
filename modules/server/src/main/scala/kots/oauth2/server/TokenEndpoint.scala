package kots.oauth2.server

import java.time.Duration

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.ClientAuthInput
import kots.oauth2.core.ExchangeTokenType
import kots.oauth2.core.KeyThumbprint
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.TokenRequest
import kots.oauth2.http.TokenLogic
import kots.oauth2.http.TokenResponse
import kots.oauth2.store.Client
import kots.oauth2.store.IssuedToken

final class TokenEndpoint[F[_]: Monad](
    authentication: ClientAuthentication[F],
    tokens: TokenService[F],
    dpop: Option[TokenEndpoint.Proofs[F]] = None
) extends TokenLogic[F] {

  def apply(
      basic: Option[String],
      parameters: Map[String, String],
      proof: Option[String] = None
  ): F[Either[OAuth2Error, TokenResponse]] =
    (dpop, proof) match {
      case (Some(config), Some(compact)) =>
        config.validator.validate(compact, TokenEndpoint.ProofMethod, config.uri).flatMap {
          case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, TokenResponse])
          case Right(jkt)  => authenticated(basic, parameters, Some(jkt))
        }
      case _ => authenticated(basic, parameters, None)
    }

  private def authenticated(
      basic: Option[String],
      parameters: Map[String, String],
      jkt: Option[KeyThumbprint]
  ): F[Either[OAuth2Error, TokenResponse]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(input)   =>
        authentication.authenticate(input).flatMap {
          case Left(error)   => Monad[F].pure(Left(error))
          case Right(client) => grant(parameters, client, jkt)
        }
    }

  private def grant(
      parameters: Map[String, String],
      client: Client,
      jkt: Option[KeyThumbprint]
  ): F[Either[OAuth2Error, TokenResponse]] = {
    def answered(issued: IssuedToken): TokenResponse =
      if (jkt.isDefined) TokenEndpoint.render(issued).copy(tokenType = TokenResponse.DpopTokenType)
      else TokenEndpoint.render(issued)
    TokenRequest.from(parameters).toEither match {
      case Left(failures) => Monad[F].pure(Left(failures.head))
      case Right(request) =>
        request match {
          case code: TokenRequest.Code =>
            tokens.authorizationCode(code, client, jkt).map(_.map(answered))
          case refresh: TokenRequest.Refresh => tokens.refresh(refresh, client, jkt).map(_.map(answered))
          case credentials: TokenRequest.ClientCredentials =>
            tokens.clientCredentials(credentials, client, jkt).map(_.map(answered))
          case device: TokenRequest.Device =>
            tokens.deviceCode(device, client, jkt).map(_.map(answered))
          case exchange: TokenRequest.Exchange =>
            tokens
              .exchange(exchange, client, jkt)
              .map(
                _.map(issued => answered(issued).copy(issuedTokenType = Some(ExchangeTokenType.AccessToken)))
              )
        }
    }
  }
}

object TokenEndpoint {

  val ProofMethod: String = "POST"

  final case class Proofs[F[_]](validator: DpopProofs[F], uri: String)

  def render(issued: IssuedToken): TokenResponse =
    TokenResponse(
      accessToken = issued.accessToken,
      expiresIn = Duration.between(issued.record.issuedAt, issued.record.accessExpiresAt).getSeconds,
      scope = issued.record.scopes,
      refreshToken = issued.refreshToken
    )
}
