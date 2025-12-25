package kots.oauth2.example

import cats.effect.Concurrent
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.client.TokenClient
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.Scopes
import org.http4s.Request
import org.http4s.Uri
import org.http4s.client.Client

final case class ProviderDocument(issuer: String, tokenEndpoint: EndpointUri)

final class ProviderExample[F[_]: Concurrent](transport: Client[F]) {

  def discover(configuration: String): F[Either[OAuth2Error, ProviderDocument]] =
    transport
      .expect[String](
        Request[F](uri = Uri.unsafeFromString(configuration)).putHeaders(
          org.http4s.headers.Accept(org.http4s.MediaType.application.json)
        )
      )
      .map(ProviderExample.document)

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
      case Left(error)     => Concurrent[F].pure(Left(error): Either[OAuth2Error, TokenClient.Grant])
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
    } yield ProviderDocument(issuer, endpoint)
}
