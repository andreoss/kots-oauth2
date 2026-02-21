package kots.oauth2.server

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

import cats.syntax.all._
import cats.Monad

import kots.oauth2.core.ClientId
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.UserCode
import kots.oauth2.core.Wire
import kots.oauth2.http.VerificationLogic
import kots.oauth2.store.DeviceRecord
import kots.oauth2.store.DeviceStore

final class DeviceVerificationEndpoint[F[_]: Monad](
    devices: DeviceStore[F],
    login: Login[F],
    secret: String
) extends VerificationLogic[F] {

  def page(session: Option[String]): F[Either[OAuth2Error, String]] =
    signedIn(session).map {
      case None    => DeviceVerificationEndpoint.anonymous.asRight[OAuth2Error]
      case Some(_) => DeviceVerificationEndpoint.entry.asRight[OAuth2Error]
    }

  def decide(
      session: Option[String],
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, String]] =
    signedIn(session).flatMap {
      case None                => DeviceVerificationEndpoint.anonymous.asRight[OAuth2Error].pure[F]
      case Some((id, subject)) =>
        entered(parameters) match {
          case None       => DeviceVerificationEndpoint.unknown.asRight[OAuth2Error].pure[F]
          case Some(code) => pending(id, subject, code, parameters)
        }
    }

  private def pending(
      id: SessionId,
      subject: Subject,
      code: UserCode,
      parameters: Map[String, String]
  ): F[Either[OAuth2Error, String]] =
    devices.pending(code).flatMap {
      case None         => DeviceVerificationEndpoint.unknown.asRight[OAuth2Error].pure[F]
      case Some(record) =>
        parameters.get(DeviceVerificationEndpoint.TokenParameter) match {
          case None =>
            DeviceVerificationEndpoint
              .confirmation(record, DeviceVerificationEndpoint.token(secret, id, code))
              .asRight[OAuth2Error]
              .pure[F]
          case Some(raw)
              if !DeviceVerificationEndpoint.same(
                raw,
                DeviceVerificationEndpoint.token(secret, id, code)
              ) =>
            DeviceVerificationEndpoint.forged.asRight[OAuth2Error].pure[F]
          case Some(_) if DeviceVerificationEndpoint.approves(parameters) =>
            devices
              .approve(code, subject)
              .map(decided =>
                if (decided) DeviceVerificationEndpoint.granted(record).asRight[OAuth2Error]
                else DeviceVerificationEndpoint.unknown.asRight[OAuth2Error]
              )
          case Some(_) =>
            devices
              .deny(code)
              .map(decided =>
                if (decided) DeviceVerificationEndpoint.refused(record).asRight[OAuth2Error]
                else DeviceVerificationEndpoint.unknown.asRight[OAuth2Error]
              )
        }
    }

  private def entered(parameters: Map[String, String]): Option[UserCode] =
    parameters
      .get(DeviceVerificationEndpoint.Parameter)
      .map(_.trim)
      .filter(_.nonEmpty)
      .flatMap(raw => UserCode.from(raw).toOption)

  private def signedIn(session: Option[String]): F[Option[(SessionId, Subject)]] =
    session.flatMap(raw => SessionId.from(raw).toOption) match {
      case None     => none[(SessionId, Subject)].pure[F]
      case Some(id) => login.subject(Some(id)).map(_.map(subject => id -> subject))
    }
}

object DeviceVerificationEndpoint {

  val Parameter: String = "user_code"

  val TokenParameter: String = "request_token"

  val DecisionParameter: String = "approve"

  val Approval: String = "yes"

  def approves(parameters: Map[String, String]): Boolean =
    parameters.get(DecisionParameter).contains(Approval)

  private val Head: String = "<!doctype html><title>Device</title>"

  val entry: String =
    Head +
      "<form method=\"post\">" +
      "<label for=\"user_code\">user_code</label>" +
      "<input id=\"user_code\" name=\"user_code\" autocomplete=\"off\">" +
      "<button type=\"submit\">continue</button>" +
      "</form>"

  def confirmation(record: DeviceRecord, token: String): String =
    Head +
      "<p>approve " + escaped(Wire[ClientId].encode(record.clientId)) +
      " for " + escaped(scopeOf(record)) + "</p>" +
      "<form method=\"post\">" +
      "<input type=\"hidden\" name=\"user_code\" value=\"" +
      escaped(Wire[UserCode].encode(record.userCode)) + "\">" +
      "<input type=\"hidden\" name=\"request_token\" value=\"" + escaped(token) + "\">" +
      "<button type=\"submit\" name=\"approve\" value=\"yes\">approve</button>" +
      "<button type=\"submit\" name=\"approve\" value=\"no\">refuse</button>" +
      "</form>"

  def granted(record: DeviceRecord): String =
    Head + "<p>approved " + escaped(Wire[ClientId].encode(record.clientId)) +
      " for " + escaped(scopeOf(record)) + "</p>"

  def refused(record: DeviceRecord): String =
    Head + "<p>refused " + escaped(Wire[ClientId].encode(record.clientId)) +
      " for " + escaped(scopeOf(record)) + "</p>"

  val unknown: String = Head + "<p>not approved</p>" + entry

  val forged: String = Head + "<p>not approved</p>"

  val anonymous: String = Head + "<p>sign in first</p>"

  def token(secret: String, id: SessionId, code: UserCode): String =
    MessageDigest
      .getInstance("SHA-256")
      .digest((secret + " " + id.value + " " + code.value).getBytes(StandardCharsets.UTF_8))
      .map(byte => f"$byte%02x")
      .mkString

  def same(left: String, right: String): Boolean =
    MessageDigest.isEqual(
      left.getBytes(StandardCharsets.UTF_8),
      right.getBytes(StandardCharsets.UTF_8)
    )

  private def scopeOf(record: DeviceRecord): String =
    if (record.scopes.value.isEmpty) "no scope" else Wire[Scopes].encode(record.scopes)

  private def escaped(raw: String): String =
    raw
      .replace("&", "&amp;")
      .replace("<", "&lt;")
      .replace(">", "&gt;")
      .replace("\"", "&quot;")
}
