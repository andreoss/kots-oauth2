package dev.oauth2.core

import cats.data.ValidatedNec
import cats.syntax.all._

sealed abstract class ClientAuthMethod(val value: String)

object ClientAuthMethod {
  case object None extends ClientAuthMethod("none")
  case object ClientSecretBasic extends ClientAuthMethod("client_secret_basic")
  case object ClientSecretPost extends ClientAuthMethod("client_secret_post")

  val all: List[ClientAuthMethod] = List(None, ClientSecretBasic, ClientSecretPost)

  def from(raw: String): Either[ParseFailure, ClientAuthMethod] =
    all.find(_.value == raw).toRight(ParseFailure("ClientAuthMethod", "not a registered method"))
}

final case class ClientAuthInput(
    basic: Option[ClientCredentials],
    clientId: Option[ClientId],
    clientSecret: Option[ClientSecret]
) {
  def subject: Option[ClientId] = basic.map(_.id).orElse(clientId)
}

object ClientAuthInput {

  def from(basic: Option[String], params: Map[String, String]): ValidatedNec[OAuth2Error, ClientAuthInput] =
    (
      credentials(basic),
      field(params, "client_id")(ClientId.from),
      field(params, "client_secret")(ClientSecret.from)
    ).mapN(ClientAuthInput.apply)

  private def credentials(basic: Option[String]): ValidatedNec[OAuth2Error, Option[ClientCredentials]] =
    basic
      .traverse(raw => ClientCredentials.fromBasic(raw).leftMap(_ => OAuth2Error.InvalidClient(): OAuth2Error))
      .toValidatedNec

  private def field[A](params: Map[String, String], name: String)(
      parse: String => Either[ParseFailure, A]
  ): ValidatedNec[OAuth2Error, Option[A]] =
    params
      .get(name)
      .traverse(parse)
      .leftMap(_ => OAuth2Error.InvalidClient(): OAuth2Error)
      .toValidatedNec
}
