package kots.oauth2.client

import cats.effect.Concurrent
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.AccessToken
import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.CodeVerifier
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import org.http4s.BasicCredentials
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Uri
import org.http4s.UrlForm
import org.http4s.client.Client
import org.http4s.headers.Authorization

final class TokenClient[F[_]: Concurrent](
    transport: Client[F],
    endpoint: EndpointUri,
    dpop: Option[DpopSigner[F]] = None
) {

  def clientCredentials(
      clientId: ClientId,
      secret: ClientSecret,
      scope: Option[Scopes],
      resource: Option[ResourceIndicator] = None
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    request(
      Map("grant_type" -> "client_credentials", "client_id" -> clientId.value) ++
        scope.map(value => "scope" -> kots.oauth2.core.Wire[Scopes].encode(value)) ++
        resource.map(value => "resource" -> value.value),
      Some(BasicCredentials(clientId.value, secret.value))
    )

  def authorizationCode(
      code: AuthorizationCode,
      verifier: CodeVerifier,
      redirectUri: Option[RedirectUri],
      clientId: ClientId,
      secret: Option[ClientSecret]
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    request(
      Map(
        "grant_type" -> "authorization_code",
        "code" -> code.value,
        "code_verifier" -> verifier.value,
        "client_id" -> clientId.value
      ) ++ redirectUri.map(uri => "redirect_uri" -> uri.value),
      secret.map(value => BasicCredentials(clientId.value, value.value))
    )

  def refresh(
      token: RefreshToken,
      clientId: ClientId,
      secret: Option[ClientSecret]
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    request(
      Map("grant_type" -> "refresh_token", "refresh_token" -> token.value, "client_id" -> clientId.value),
      secret.map(value => BasicCredentials(clientId.value, value.value))
    )

  def device(
      code: kots.oauth2.core.DeviceCode,
      clientId: ClientId,
      secret: Option[ClientSecret]
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    request(
      Map(
        "grant_type" -> "urn:ietf:params:oauth:grant-type:device_code",
        "device_code" -> code.value,
        "client_id" -> clientId.value
      ),
      secret.map(value => BasicCredentials(clientId.value, value.value))
    )

  private def request(
      form: Map[String, String],
      credentials: Option[BasicCredentials]
  ): F[Either[OAuth2Error, TokenClient.Grant]] =
    attempt(form, credentials, retry = dpop.isDefined)

  private def attempt(
      form: Map[String, String],
      credentials: Option[BasicCredentials],
      retry: Boolean
  ): F[Either[OAuth2Error, TokenClient.Grant]] = {
    val base = Request[F](method = Method.POST, uri = Uri.unsafeFromString(endpoint.value))
      .withEntity(UrlForm(form.toSeq: _*))
    val sent = credentials.fold(base)(value => base.putHeaders(Authorization(value)))
    dpop match {
      case None         => transport.run(sent).use(answer)
      case Some(signer) =>
        signer.proof(Method.POST.name, endpoint.value).flatMap {
          case Left(failure) =>
            Concurrent[F].pure(
              Left(
                OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
              ): Either[OAuth2Error, TokenClient.Grant]
            )
          case Right(proof) =>
            transport
              .run(sent.putHeaders(org.http4s.Header.Raw(TokenClient.ProofHeader, proof)))
              .use { response =>
                val demanded = response.headers
                  .get(TokenClient.NonceHeader)
                  .map(_.head.value)
                signer.learn(demanded).flatMap(_ => answer(response))
              }
              .flatMap {
                case Left(error) if error.code == TokenClient.NonceDemand && retry =>
                  attempt(form, credentials, retry = false)
                case result => Concurrent[F].pure(result)
              }
        }
    }
  }

  private def answer(response: Response[F]): F[Either[OAuth2Error, TokenClient.Grant]] =
    response.bodyText.compile.string.map { text =>
      if (response.status.isSuccess) TokenClient.grant(text)
      else TokenClient.refusal(response.status.code, text)
    }
}

object TokenClient {

  val ProofHeader: org.typelevel.ci.CIString = org.typelevel.ci.CIString("DPoP")

  val NonceHeader: org.typelevel.ci.CIString = org.typelevel.ci.CIString("DPoP-Nonce")

  val NonceDemand: String = "use_dpop_nonce"

  final case class Grant(
      accessToken: AccessToken,
      tokenType: String,
      expiresIn: Long,
      refreshToken: Option[RefreshToken],
      scope: Scopes
  )

  private val unreadable: OAuth2Error = OAuth2Error.ServerError(Some("unreadable answer"))

  private def seconds(cursor: io.circe.HCursor): Either[OAuth2Error, Long] =
    cursor.get[Long]("expires_in") match {
      case Right(value) => Right(value)
      case Left(_)      =>
        cursor
          .get[String]("expires_in")
          .left
          .map(_ => unreadable)
          .flatMap(_.toLongOption.toRight(unreadable))
    }

  private[client] def grant(text: String): Either[OAuth2Error, Grant] =
    for {
      json <- io.circe.parser.parse(text).left.map(_ => unreadable)
      cursor = json.hcursor
      access <- cursor
        .get[String]("access_token")
        .left
        .map(_ => unreadable)
        .flatMap(raw => AccessToken.from(raw).left.map(_ => unreadable))
      tokenType <- cursor.get[String]("token_type").left.map(_ => unreadable)
      expiresIn <- seconds(cursor)
      refresh <- cursor
        .get[String]("refresh_token")
        .toOption
        .fold(
          Right(None): Either[OAuth2Error, Option[RefreshToken]]
        )(raw =>
          RefreshToken.from(raw).map(token => Some(token): Option[RefreshToken]).left.map(_ => unreadable)
        )
      scope <- cursor
        .get[String]("scope")
        .toOption
        .filter(_.nonEmpty)
        .fold(
          Right(Scopes.empty): Either[OAuth2Error, Scopes]
        )(raw => Scopes.parse(raw).left.map(_ => unreadable))
    } yield Grant(access, tokenType, expiresIn, refresh, scope)

  private[client] def refusal(status: Int, text: String): Either[OAuth2Error, Grant] = {
    val fields = io.circe.parser
      .parse(text)
      .toOption
      .flatMap(_.asObject)
      .map(_.toMap.collect { case (name, value) if value.isString => name -> value.asString.getOrElse("") })
      .getOrElse(Map.empty[String, String])
    OAuth2Error.fromWire(status, fields) match {
      case Right(error) => Left(error)
      case Left(_)      => Left(unreadable)
    }
  }
}
