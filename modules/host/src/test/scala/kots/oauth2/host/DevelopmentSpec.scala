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

  private def grants(text: String): List[String] =
    io.circe.parser
      .parse(text)
      .toOption
      .flatMap(_.hcursor.get[List[String]]("grant_types_supported").toOption)
      .getOrElse(sys.error(s"no grant_types_supported in $text"))

  test("the served metadata offers the assertion grant only where issuers are configured") {
    def document(issuers: Option[kots.oauth2.server.AssertionIssuers[IO]]): IO[String] =
      Development.assembled[IO](issuers).flatMap { case (served, _) =>
        served
          .run(
            Request[IO](
              uri = Uri.unsafeFromString(
                "http://localhost/.well-known/oauth-authorization-server"
              )
            )
          )
          .value
          .flatMap(_.fold(IO.pure(""))(_.bodyText.compile.string))
      }
    for {
      without <- document(None)
      configured <- document(Some(kots.oauth2.server.AssertionIssuers.static[IO](Map.empty)))
    } yield {
      assert(!grants(without).contains(kots.oauth2.core.GrantType.IdJag.value))
      assert(grants(configured).contains(kots.oauth2.core.GrantType.IdJag.value))
    }
  }

  test("the trusted issuer list is read from configuration and fails closed") {
    assertEquals(DevServer.trusted(None), Right(Nil))
    assertEquals(DevServer.trusted(Some("")), Right(Nil))
    assertEquals(
      DevServer.trusted(Some("https://idp.example, https://other.example")).map(_.map(_.value)),
      Right(List("https://idp.example", "https://other.example"))
    )
    assert(DevServer.trusted(Some("not an issuer")).isLeft)
  }

  test("the discovered document leads back to the server that published it") {
    val accepts = org.http4s.headers.Accept(org.http4s.MediaType.application.json)
    val bound = for {
      server <- Development.server[IO](Port.fromInt(28100).get, None, "http://localhost:28100")
      client <- EmberClientBuilder.default[IO].build
    } yield (server, client)
    bound.use {
      case (server, client) =>
          val base = s"http://localhost:${server.address.getPort}"
          for {
            metadata <- client.expect[String](
              Request[IO](
                uri = Uri.unsafeFromString(s"$base/.well-known/oauth-authorization-server"),
                headers = org.http4s.Headers(accepts)
              )
            )
            token <- client
              .run(
                Request[IO](
                  method = Method.POST,
                  uri = Uri.unsafeFromString(field(metadata, "token_endpoint")),
                  headers = org.http4s.Headers(
                    Authorization(
                      BasicCredentials(Development.SeedClientId, Development.SeedClientSecret)
                    ),
                    accepts
                  )
                ).withEntity(UrlForm("grant_type" -> "client_credentials"))
              )
              .use(response => IO.pure(response.status))
        } yield {
          assertEquals(field(metadata, "issuer"), base)
          assertEquals(token, Status.Ok)
        }
    }
  }

  test("the served issuer is read from configuration and falls back to the bound address") {
    assertEquals(DevServer.served(None, 8080), Right("http://localhost:8080"))
    assertEquals(DevServer.served(Some(""), 9000), Right("http://localhost:9000"))
    assertEquals(DevServer.served(Some("https://issuer.example"), 8080), Right("https://issuer.example"))
    assert(DevServer.served(Some("not an issuer"), 8080).isLeft)
  }
}
