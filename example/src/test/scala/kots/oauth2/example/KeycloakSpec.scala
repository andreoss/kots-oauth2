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

  private def adminGrant(transport: Client[IO]): IO[(String, String)] =
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
      .map { text =>
        val cursor = io.circe.parser.parse(text).toOption.map(_.hcursor)
        val access = cursor.flatMap(_.get[String]("access_token").toOption)
        val refresh = cursor.flatMap(_.get[String]("refresh_token").toOption)
        (access.getOrElse(sys.error("no admin token")), refresh.getOrElse(sys.error("no admin refresh")))
      }

  private val registration: String =
    """{"clientId":"example-client","secret":"example-secret","serviceAccountsEnabled":true,""" +
      """"publicClient":false,"protocol":"openid-connect",""" +
      """"attributes":{"access.token.header.type.rfc9068":"true"}}"""

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
          val example = new ProviderExample[IO](transport)
          val clock = new kots.oauth2.core.Clock[IO] {
            def instant: IO[java.time.Instant] = IO.realTimeInstant
          }
          for {
            _ <- Containers.awaitHttp(transport, s"$base/realms/master")
            adminPair <- adminGrant(transport)
            (admin, adminRefresh) = adminPair
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
            document <- example
              .discover(s"$base/realms/master/.well-known/openid-configuration")
              .map(_.toOption.get)
            granted <- example.credentials(
              document.tokenEndpoint,
              unsafe(ClientId.from("example-client")),
              unsafe(ClientSecret.from("example-secret")),
              None
            )
            published <- example.keys(document.jwksUri.get).map(_.toOption.get)
            guard = new kots.oauth2.client.BearerGuard[IO](
              IO.pure(Right(published)),
              unsafe(kots.oauth2.core.Issuer.from(document.issuer)),
              clock,
              tokenTypes = Set(kots.oauth2.jose.Jwt.AccessTokenType, "JWT")
            )
            accepted <- guard.verify(
              Some("Bearer " + granted.toOption.get.accessToken.value),
              kots.oauth2.core.Scopes.empty
            )
            strangers = new kots.oauth2.client.BearerGuard[IO](
              IO.pure(Right(published)),
              unsafe(kots.oauth2.core.Issuer.from("https://other.example")),
              clock
            )
            refused <- strangers.verify(
              Some("Bearer " + granted.toOption.get.accessToken.value),
              kots.oauth2.core.Scopes.empty
            )
            refreshed <- new kots.oauth2.client.TokenClient[IO](transport, document.tokenEndpoint)
              .refresh(
                unsafe(kots.oauth2.core.RefreshToken.from(adminRefresh)),
                unsafe(ClientId.from("admin-cli")),
                None
              )
          } yield {
            assertEquals(created, Status.Created)
            val grant = granted.toOption.get
            assert(grant.tokenType.equalsIgnoreCase("bearer"))
            assertEquals(grant.accessToken.value.count(_ == '.'), 2)
            assert(grant.expiresIn > 0L)
            assert(published.keys.nonEmpty)
            val claims = accepted.toOption.get
            assertEquals(claims.clientId.value, "example-client")
            assertEquals(claims.issuer.value, document.issuer)
            assert(refused.left.toOption.exists(_.header.contains("invalid_token")))
            val renewed = refreshed.toOption.get
            assert(renewed.accessToken.value.nonEmpty)
            assert(renewed.refreshToken.isDefined)
          }
        }
      }
  }
}
