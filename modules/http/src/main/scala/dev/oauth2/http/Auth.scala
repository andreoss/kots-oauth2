package dev.oauth2.http

import dev.oauth2.core.OAuth2Error
import sttp.model.headers.WWWAuthenticateChallenge
import sttp.tapir.Codec
import sttp.tapir.CodecFormat
import sttp.tapir.EndpointInput
import sttp.tapir._

object Auth {

  val BasicSchemeName: String = "client_secret_basic"

  implicit val basicValue: Codec[List[String], Option[String], CodecFormat.TextPlain] =
    Codec.listHeadOption(Codec.string)

  val challenge: WWWAuthenticateChallenge = WWWAuthenticateChallenge.basic(OAuth2Error.BasicRealm)

  val basic: EndpointInput.Auth[Option[String], EndpointInput.AuthType.Http] =
    auth.basic[Option[String]](challenge).securitySchemeName(BasicSchemeName)
}
