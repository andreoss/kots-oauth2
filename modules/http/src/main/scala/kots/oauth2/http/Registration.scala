package kots.oauth2.http

import cats.syntax.traverse._

import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientRegistration
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.Scopes
import io.circe.Json

object Registration {

  val RedirectUris: String = "redirect_uris"

  val TokenEndpointAuthMethod: String = "token_endpoint_auth_method"

  val Scope: String = "scope"

  val SecretExpiresAt: String = "client_secret_expires_at"

  val Registrable: Set[ClientAuthMethod] =
    Set(ClientAuthMethod.None, ClientAuthMethod.ClientSecretBasic, ClientAuthMethod.ClientSecretPost)

  def parse(body: Map[String, Json]): Either[OAuth2Error, ClientRegistration] =
    for {
      uris <- redirects(body)
      method <- authMethod(body)
      scopes <- scopesOf(body)
    } yield ClientRegistration(uris, method, scopes)

  private def redirects(body: Map[String, Json]): Either[OAuth2Error, Set[RedirectUri]] =
    body.get(RedirectUris).flatMap(_.asArray) match {
      case Some(values) if values.nonEmpty =>
        values.toList
          .traverse(value =>
            value.asString
              .toRight(OAuth2Error.InvalidRedirectUri(): OAuth2Error)
              .flatMap(raw =>
                RedirectUri.from(raw).left.map(_ => OAuth2Error.InvalidRedirectUri(): OAuth2Error)
              )
          )
          .map(_.toSet)
      case _ => Left(OAuth2Error.InvalidRedirectUri(): OAuth2Error)
    }

  private def authMethod(body: Map[String, Json]): Either[OAuth2Error, ClientAuthMethod] =
    body.get(TokenEndpointAuthMethod) match {
      case None        => Right(ClientAuthMethod.ClientSecretBasic)
      case Some(value) =>
        value.asString
          .toRight(OAuth2Error.InvalidClientMetadata(): OAuth2Error)
          .flatMap(raw =>
            ClientAuthMethod.from(raw).left.map(_ => OAuth2Error.InvalidClientMetadata(): OAuth2Error)
          )
          .flatMap(method =>
            Either
              .cond(Registrable.contains(method), method, OAuth2Error.InvalidClientMetadata(): OAuth2Error)
          )
    }

  private def scopesOf(body: Map[String, Json]): Either[OAuth2Error, Scopes] =
    body.get(Scope) match {
      case None        => Right(Scopes.empty)
      case Some(value) =>
        value.asString
          .toRight(OAuth2Error.InvalidClientMetadata(): OAuth2Error)
          .flatMap(raw => Scopes.parse(raw).left.map(_ => OAuth2Error.InvalidClientMetadata(): OAuth2Error))
    }
}
