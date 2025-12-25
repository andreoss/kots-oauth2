package kots.oauth2.example

import scala.concurrent.duration._

import cats.effect.IO
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ParseFailure
import munit.CatsEffectSuite
import org.http4s.MediaType
import org.http4s.Method
import org.http4s.Request
import org.http4s.Status
import org.http4s.Uri
import org.http4s.UrlForm
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.Authorization
import org.http4s.headers.`Content-Type`

class KeycloakSpec extends CatsEffectSuite {

  override def munitIOTimeout: Duration = 5.minutes

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val Port: Int = 28080

  private def base: String = s"http://localhost:$Port"

  private def adminToken(transport: Client[IO]): IO[String] =
    transport
      .expect[String](
        Request[IO](
          method = Method.POST,
          uri = Uri.unsafeFromString(s"$base/realms/master/protocol/openid-connect/token")
        ).withEntity(
          UrlForm(
            "grant_type" -> "password",
            "client_id" -> "admin-cli",
            "username" -> "admin",
            "password" -> "admin"
          )
        )
      )
      .map(text =>
        io.circe.parser
          .parse(text)
          .toOption
          .flatMap(_.hcursor.get[String]("access_token").toOption)
          .getOrElse(sys.error("no admin token"))
      )

  private val registration: String =
    """{"clientId":"example-client","secret":"example-secret","serviceAccountsEnabled":true,""" +
      """"publicClient":false,"protocol":"openid-connect"}"""

  test("a grant is obtained from the second independent provider through discovery") {
    assume(Containers.enabled, "the container runtime is not available or e2e is not enabled")
    val keycloak = Containers.container(
      List(
        "-p",
        s"$Port:8080",
        "-e",
        "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
        "-e",
        "KC_BOOTSTRAP_ADMIN_PASSWORD=admin",
        "-e",
        "KEYCLOAK_ADMIN=admin",
        "-e",
        "KEYCLOAK_ADMIN_PASSWORD=admin",
        "quay.io/keycloak/keycloak:26.0",
        "start-dev"
      )
    )
    keycloak
      .use { _ =>
        EmberClientBuilder.default[IO].build.use { transport =>
          for {
            _ <- Containers.awaitHttp(transport, s"$base/realms/master")
            admin <- adminToken(transport)
            created <- transport.status(
              Request[IO](
                method = Method.POST,
                uri = Uri.unsafeFromString(s"$base/admin/realms/master/clients"),
                headers = org.http4s.Headers(
                  Authorization(org.http4s.Credentials.Token(org.http4s.AuthScheme.Bearer, admin))
                )
              ).withEntity(registration)
                .withContentType(`Content-Type`(MediaType.application.json))
            )
            granted <- new ProviderExample[IO](transport).grantFromDiscovery(
              s"$base/realms/master/.well-known/openid-configuration",
              unsafe(ClientId.from("example-client")),
              unsafe(ClientSecret.from("example-secret"))
            )
          } yield {
            assertEquals(created, Status.Created)
            val grant = granted.toOption.get
            assert(grant.tokenType.equalsIgnoreCase("bearer"))
            assertEquals(grant.accessToken.value.count(_ == '.'), 2)
            assert(grant.expiresIn > 0L)
          }
        }
      }
  }
}
