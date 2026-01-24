package kots.oauth2.server

import cats.syntax.all._
import cats.Monad

import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.UserCode
import kots.oauth2.http.VerificationLogic
import kots.oauth2.store.DeviceStore

final class DeviceVerificationEndpoint[F[_]: Monad](
    devices: DeviceStore[F],
    login: Login[F]
) extends VerificationLogic[F] {

  def page: F[Either[OAuth2Error, String]] =
    DeviceVerificationEndpoint.form.asRight[OAuth2Error].pure[F]

  def decide(parameters: Map[String, String]): F[Either[OAuth2Error, String]] =
    parameters.get(DeviceVerificationEndpoint.Parameter).map(_.trim).filter(_.nonEmpty) match {
      case None      => DeviceVerificationEndpoint.refused.asRight[OAuth2Error].pure[F]
      case Some(raw) =>
        UserCode.from(raw) match {
          case Left(_)     => DeviceVerificationEndpoint.refused.asRight[OAuth2Error].pure[F]
          case Right(code) => approved(code)
        }
    }

  private def approved(code: UserCode): F[Either[OAuth2Error, String]] =
    login.subject.flatMap {
      case None          => DeviceVerificationEndpoint.anonymous.asRight[OAuth2Error].pure[F]
      case Some(subject) =>
        devices.approve(code, subject).map { decided =>
          if (decided) DeviceVerificationEndpoint.granted.asRight[OAuth2Error]
          else DeviceVerificationEndpoint.refused.asRight[OAuth2Error]
        }
    }
}

object DeviceVerificationEndpoint {

  val Parameter: String = "user_code"

  val form: String =
    "<!doctype html><title>Device</title>" +
      "<form method=\"post\">" +
      "<label for=\"user_code\">user_code</label>" +
      "<input id=\"user_code\" name=\"user_code\" autocomplete=\"off\">" +
      "<button type=\"submit\">approve</button>" +
      "</form>"

  val granted: String = "<!doctype html><title>Device</title><p>approved</p>"

  val refused: String = "<!doctype html><title>Device</title><p>not approved</p>" + form

  val anonymous: String = "<!doctype html><title>Device</title><p>sign in first</p>"
}
