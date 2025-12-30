package kots.oauth2.host

import cats.effect.IO
import com.comcast.ip4s.Port
import munit.CatsEffectSuite
import org.http4s.BasicCredentials
import org.http4s.Method
import org.http4s.Request
import org.http4s.Status
import org.http4s.Uri
import org.http4s.UrlForm
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.Authorization

class DevelopmentSpec extends CatsEffectSuite {

  private def field(text: String, name: String): String =
    io.circe.parser
      .parse(text)
      .toOption
      .flatMap(_.hcursor.get[String](name).toOption)
      .getOrElse(sys.error(s"no $name in $text"))

  test("the development server answers discovery and issues a seeded token over real http") {
    val bound = for {
      server <- Development.server[IO](Port.fromInt(0).get)
      client <- EmberClientBuilder.default[IO].build
    } yield (server, client)
    bound.use { case (server, client) =>
      val base = s"http://localhost:${server.address.getPort}"
      val accepts = org.http4s.headers.Accept(org.http4s.MediaType.application.json)
      for {
        metadata <- client.expect[String](
          Request[IO](
            uri = Uri.unsafeFromString(s"$base/.well-known/oauth-authorization-server"),
            headers = org.http4s.Headers(accepts)
          )
        )
        token <- client.expect[String](
          Request[IO](
            method = Method.POST,
            uri = Uri.unsafeFromString(s"$base/token"),
            headers = org.http4s.Headers(
              Authorization(BasicCredentials(Development.SeedClientId, Development.SeedClientSecret)),
              accepts
            )
          ).withEntity(
            UrlForm(
              "grant_type" -> "client_credentials",
              "client_id" -> Development.SeedClientId
            )
          )
        )
        jwks <- client.status(Request[IO](uri = Uri.unsafeFromString(s"$base/jwks")))
      } yield {
        assertEquals(field(metadata, "issuer"), Development.SeedIssuer)
        assertEquals(
          field(metadata, "jwks_uri"),
          s"${Development.SeedIssuer}/${kots.oauth2.http.Endpoints.JwksPath}"
        )
        assertEquals(
          field(metadata, "registration_endpoint"),
          s"${Development.SeedIssuer}/${kots.oauth2.http.Endpoints.RegisterPath}"
        )
        assertEquals(
          field(metadata, "device_authorization_endpoint"),
          s"${Development.SeedIssuer}/${kots.oauth2.http.Endpoints.DeviceAuthorizationPath}"
        )
        assert(field(token, "access_token").count(_ == '.') == 2)
        assertEquals(jwks, Status.Ok)
      }
    }
  }
}
