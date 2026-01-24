package kots.oauth2.server

import java.time.Duration

import cats.syntax.all._
import cats.Monad

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
      proof: Option[String] = None,
      certificate: Option[String] = None
  ): F[Either[OAuth2Error, TokenResponse]] =
    certified(certificate) match {
      case Left(error)      => error.asLeft[TokenResponse].pure[F]
      case Right(presented) =>
        (dpop, proof) match {
          case (Some(config), Some(compact)) =>
            config.validator.validate(compact, TokenEndpoint.ProofMethod, config.uri).flatMap {
              case Left(error) => error.asLeft[TokenResponse].pure[F]
              case Right(jkt)  => authenticated(basic, parameters, Some(jkt), presented)
            }
          case _ => authenticated(basic, parameters, None, presented)
        }
    }

  private def certified(
      certificate: Option[String]
  ): Either[OAuth2Error, Option[kots.oauth2.core.ClientCertificate]] =
    certificate match {
      case None      => Right(None)
      case Some(raw) =>
        Certificates.parse(raw) match {
          case Left(_)       => Left(OAuth2Error.InvalidClient(): OAuth2Error)
          case Right(parsed) => Right(Some(parsed))
        }
    }

  private def authenticated(
      basic: Option[String],
      parameters: Map[String, String],
      jkt: Option[KeyThumbprint],
      certificate: Option[kots.oauth2.core.ClientCertificate]
  ): F[Either[OAuth2Error, TokenResponse]] =
    ClientAuthInput.from(basic, parameters).toEither match {
      case Left(failures) => failures.head.asLeft.pure[F]
      case Right(input)   =>
        authentication.authenticate(input.copy(certificate = certificate)).flatMap {
          case Left(error)   => error.asLeft.pure[F]
          case Right(client) => grant(parameters, client, jkt, TokenEndpoint.bound(client, certificate))
        }
    }

  private def grant(
      parameters: Map[String, String],
      client: Client,
      jkt: Option[KeyThumbprint],
      x5t: Option[kots.oauth2.core.CertificateThumbprint]
  ): F[Either[OAuth2Error, TokenResponse]] = {
    def answered(issued: IssuedToken): TokenResponse =
      if (jkt.isDefined) TokenEndpoint.render(issued).copy(tokenType = TokenResponse.DpopTokenType)
      else TokenEndpoint.render(issued)
    val enriched =
      if (parameters.contains("client_id")) parameters
      else parameters + ("client_id" -> client.id.value)
    TokenRequest.from(enriched).toEither match {
      case Left(failures) => failures.head.asLeft.pure[F]
      case Right(request) =>
        request match {
          case code: TokenRequest.Code =>
            tokens.authorizationCode(code, client, jkt, x5t).map(_.map(answered))
          case refresh: TokenRequest.Refresh =>
            tokens.refresh(refresh, client, jkt, x5t).map(_.map(answered))
          case credentials: TokenRequest.ClientCredentials =>
            tokens.clientCredentials(credentials, client, jkt, x5t).map(_.map(answered))
          case device: TokenRequest.Device =>
            tokens.deviceCode(device, client, jkt, x5t).map(_.map(answered))
          case exchange: TokenRequest.Exchange =>
            tokens
              .exchange(exchange, client, jkt, x5t)
              .map(
                _.map(issued => answered(issued).copy(issuedTokenType = Some(ExchangeTokenType.AccessToken)))
              )
          case idjag: TokenRequest.IdJag =>
            tokens.idJag(idjag, client, jkt, x5t).map(_.map(answered))
        }
    }
  }
}

object TokenEndpoint {

  val ProofMethod: String = "POST"

  private[server] def bound(
      client: Client,
      certificate: Option[kots.oauth2.core.ClientCertificate]
  ): Option[kots.oauth2.core.CertificateThumbprint] =
    client.authMethod match {
      case kots.oauth2.core.ClientAuthMethod.TlsClientAuth |
          kots.oauth2.core.ClientAuthMethod.SelfSignedTlsClientAuth =>
        certificate.map(_.thumbprint)
      case _ => None
    }

  final case class Proofs[F[_]](validator: DpopProofs[F], uri: String)

  def render(issued: IssuedToken): TokenResponse =
    TokenResponse(
      accessToken = issued.accessToken,
      expiresIn = Duration.between(issued.record.issuedAt, issued.record.accessExpiresAt).getSeconds,
      scope = issued.record.scopes,
      refreshToken = issued.refreshToken
    )
}
