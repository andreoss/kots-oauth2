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
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.`Content-Type`

class HydraSpec extends CatsEffectSuite {

  override def munitIOTimeout: Duration = 5.minutes

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val PublicPort: Int = 24444

  private val AdminPort: Int = 24445

  private val registration: String =
    """{"client_id":"example-client","client_secret":"example-secret",""" +
      """"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_basic"}"""

  test("a grant is obtained from the first independent provider through discovery") {
    assume(Containers.enabled, "the container runtime is not available or e2e is not enabled")
    val hydra = Containers.container(
      List(
        "-p",
        s"$PublicPort:4444",
        "-p",
        s"$AdminPort:4445",
        "-e",
        "DSN=memory",
        "-e",
        "SECRETS_SYSTEM=example-system-secret-with-32-chars",
        "-e",
        "STRATEGIES_ACCESS_TOKEN=jwt",
        "-e",
        s"URLS_SELF_ISSUER=http://localhost:$PublicPort",
        "oryd/hydra:v2.2.0",
        "serve",
        "all",
        "--dev"
      )
    )
    hydra
      .use { _ =>
        EmberClientBuilder.default[IO].build.use { transport =>
          val example = new ProviderExample[IO](transport)
          val clock = new kots.oauth2.core.Clock[IO] {
            def instant: IO[java.time.Instant] = IO.realTimeInstant
          }
          for {
            _ <- Containers.awaitHttp(transport, s"http://localhost:$AdminPort/health/ready")
            created <- transport.status(
              Request[IO](
                method = Method.POST,
                uri = Uri.unsafeFromString(s"http://localhost:$AdminPort/admin/clients")
              ).withEntity(registration)
                .withContentType(`Content-Type`(MediaType.application.json))
            )
            document <- example
              .discover(s"http://localhost:$PublicPort/.well-known/openid-configuration")
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
          } yield {
            assertEquals(created, Status.Created)
            val grant = granted.toOption.get
            assert(grant.tokenType.equalsIgnoreCase("bearer"))
            assert(grant.accessToken.value.nonEmpty)
            assert(grant.expiresIn > 0L)
            assert(published.keys.nonEmpty)
            val claims = accepted.toOption.get
            assertEquals(claims.clientId.value, "example-client")
            assertEquals(claims.issuer.value, document.issuer)
          }
        }
      }
  }
}
