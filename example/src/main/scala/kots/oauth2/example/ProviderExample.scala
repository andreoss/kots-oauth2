package kots.oauth2.example

import cats.syntax.all._
import cats.effect.Concurrent

import kots.oauth2.client.TokenClient
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.Scopes
import org.http4s.Request
import org.http4s.Uri
import org.http4s.client.Client

final case class ProviderDocument(
    issuer: String,
    tokenEndpoint: EndpointUri,
    jwksUri: Option[EndpointUri]
)

final class ProviderExample[F[_]: Concurrent](transport: Client[F]) {

  def discover(configuration: String): F[Either[OAuth2Error, ProviderDocument]] =
    transport
      .expect[String](
        Request[F](uri = Uri.unsafeFromString(configuration)).putHeaders(
          org.http4s.headers.Accept(org.http4s.MediaType.application.json)
        )
      )
      .map(ProviderExample.document)

  def keys(jwksUri: EndpointUri): F[Either[OAuth2Error, kots.oauth2.jose.Jwks]] =
    transport
      .expect[String](
        Request[F](uri = Uri.unsafeFromString(jwksUri.value)).putHeaders(
          org.http4s.headers.Accept(org.http4s.MediaType.application.json)
        )
      )
      .map(text =>
        kots.oauth2.client.Discovery
          .keys(text)
          .left
          .map(failure => OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}")))
      )

  def credentials(
      tokenEndpoint: EndpointUri,
      clientId: ClientId,
      secret: ClientSecret,
      scope: Option[Scopes]
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    new TokenClient[F](transport, tokenEndpoint).clientCredentials(clientId, secret, scope)

  def grantFromDiscovery(
      configuration: String,
      clientId: ClientId,
      secret: ClientSecret,
      scope: Option[Scopes] = None
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    discover(configuration).flatMap {
      case Left(error)     => error.asLeft[TokenClient.Grant].pure[F]
      case Right(document) => credentials(document.tokenEndpoint, clientId, secret, scope)
    }
}

object ProviderExample {

  private val unreadable: OAuth2Error = OAuth2Error.ServerError(Some("unreadable document"))

  private[example] def document(text: String): Either[OAuth2Error, ProviderDocument] =
    for {
      json <- io.circe.parser.parse(text).left.map(_ => unreadable)
      cursor = json.hcursor
      issuer <- cursor.get[String]("issuer").left.map(_ => unreadable)
      endpoint <- cursor
        .get[String]("token_endpoint")
        .left
        .map(_ => unreadable)
        .flatMap(raw => EndpointUri.from(raw).left.map(_ => unreadable))
      jwks = cursor.get[String]("jwks_uri").toOption.flatMap(raw => EndpointUri.from(raw).toOption)
    } yield ProviderDocument(issuer, endpoint, jwks)
}
