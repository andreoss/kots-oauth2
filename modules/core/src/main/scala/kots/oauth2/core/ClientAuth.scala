package kots.oauth2.core

import cats.data.ValidatedNec
import cats.syntax.all._

sealed abstract class ClientAuthMethod(val value: String)

object ClientAuthMethod {
  case object None extends ClientAuthMethod("none")
  case object ClientSecretBasic extends ClientAuthMethod("client_secret_basic")
  case object ClientSecretPost extends ClientAuthMethod("client_secret_post")
  case object PrivateKeyJwt extends ClientAuthMethod("private_key_jwt")
  case object ClientSecretJwt extends ClientAuthMethod("client_secret_jwt")
  case object TlsClientAuth extends ClientAuthMethod("tls_client_auth")
  case object SelfSignedTlsClientAuth extends ClientAuthMethod("self_signed_tls_client_auth")

  val all: List[ClientAuthMethod] =
    List(
      None,
      ClientSecretBasic,
      ClientSecretPost,
      PrivateKeyJwt,
      ClientSecretJwt,
      TlsClientAuth,
      SelfSignedTlsClientAuth
    )

  def from(raw: String): Either[ParseFailure, ClientAuthMethod] =
    all.find(_.value == raw).toRight(ParseFailure("ClientAuthMethod", "not a registered method"))
}

final case class ClientAssertion private (value: String)

object ClientAssertion {

  val Type: String = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  def from(raw: String): Either[ParseFailure, ClientAssertion] =
    Text.printableToken("ClientAssertion", raw).map(new ClientAssertion(_))
}

final case class CertificateSubject private (value: String)

object CertificateSubject {
  def from(raw: String): Either[ParseFailure, CertificateSubject] =
    Text.line("CertificateSubject", raw).map(new CertificateSubject(_))
}

final case class CertificateThumbprint private (value: String)

object CertificateThumbprint {
  def from(raw: String): Either[ParseFailure, CertificateThumbprint] =
    Text.printable("CertificateThumbprint", raw).map(new CertificateThumbprint(_))
}

final case class ClientCertificate(subject: CertificateSubject, thumbprint: CertificateThumbprint)

final case class ClientAuthInput(
    basic: Option[ClientCredentials],
    clientId: Option[ClientId],
    clientSecret: Option[ClientSecret],
    assertion: Option[ClientAssertion],
    certificate: Option[ClientCertificate] = scala.None
) {
  def subject: Option[ClientId] = basic.map(_.id).orElse(clientId)
}

object ClientAuthInput {

  def from(basic: Option[String], params: Map[String, String]): ValidatedNec[OAuth2Error, ClientAuthInput] =
    (
      credentials(basic),
      field(params, "client_id")(ClientId.from),
      field(params, "client_secret")(ClientSecret.from),
      assertionOf(params)
    ).mapN(ClientAuthInput(_, _, _, _))

  private def assertionOf(params: Map[String, String]): ValidatedNec[OAuth2Error, Option[ClientAssertion]] =
    (params.get("client_assertion"), params.get("client_assertion_type")) match {
      case (scala.None, scala.None)                => none[ClientAssertion].validNec
      case (Some(raw), Some(ClientAssertion.Type)) =>
        ClientAssertion
          .from(raw)
          .map(_.some)
          .leftMap(_ => OAuth2Error.InvalidClient(): OAuth2Error)
          .toValidatedNec
      case _ => (OAuth2Error.InvalidClient(): OAuth2Error).invalidNec
    }

  private def credentials(basic: Option[String]): ValidatedNec[OAuth2Error, Option[ClientCredentials]] =
    basic
      .traverse(raw =>
        ClientCredentials.fromBasic(raw).leftMap(_ => OAuth2Error.InvalidClient(): OAuth2Error)
      )
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
