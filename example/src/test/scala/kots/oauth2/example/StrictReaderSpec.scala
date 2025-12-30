package kots.oauth2.example

import scala.concurrent.duration._

import cats.effect.IO
import com.comcast.ip4s.{Port => NetworkPort}
import kots.oauth2.host.Development
import munit.CatsEffectSuite
import org.http4s.BasicCredentials
import org.http4s.Method
import org.http4s.Request
import org.http4s.Status
import org.http4s.Uri
import org.http4s.UrlForm
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.Authorization
import io.circe.Json

class StrictReaderSpec extends CatsEffectSuite {

  override def munitIOTimeout: Duration = 2.minutes

  private val Port: Int = 28110

  private val issuer: String = s"http://localhost:$Port"

  private def credentials: Authorization =
    Authorization(BasicCredentials(Development.SeedClientId, Development.SeedClientSecret))

  private val accepts = org.http4s.headers.Accept(org.http4s.MediaType.application.json)

  private def form(transport: Client[IO], path: String, fields: (String, String)*): IO[(Status, Json)] =
    transport
      .run(
        Request[IO](
          method = Method.POST,
          uri = Uri.unsafeFromString(s"$issuer/$path"),
          headers = org.http4s.Headers(credentials, accepts)
        ).withEntity(UrlForm(fields: _*))
      )
      .use(response =>
        response.bodyText.compile.string.map(text =>
          response.status -> io.circe.parser.parse(text).getOrElse(Json.Null)
        )
      )

  private def number(document: Json, name: String): Option[Long] =
    document.hcursor.downField(name).focus.flatMap(_.asNumber).flatMap(_.toLong)

  private def boolean(document: Json, name: String): Option[Boolean] =
    document.hcursor.downField(name).focus.flatMap(_.asBoolean)

  private def text(document: Json, name: String): Option[String] =
    document.hcursor.downField(name).focus.flatMap(_.asString)

  test("a reader that takes every member at its declared type completes the flows") {
    val bound = for {
      server <- Development.server[IO](NetworkPort.fromInt(Port).get, None, issuer)
      transport <- EmberClientBuilder.default[IO].build
    } yield (server, transport)
    bound.use { case (_, transport) =>
      for {
        granted <- form(transport, "token", "grant_type" -> "client_credentials", "scope" -> "read")
        access = text(granted._2, "access_token").getOrElse(sys.error("no access token"))
        introspected <- form(transport, "introspection", "token" -> access)
        device <- form(transport, "device_authorization", "scope" -> "read")
        pushed <- form(
          transport,
          "par",
          "response_type" -> "code",
          "redirect_uri" -> "https://client.example/cb",
          "scope" -> "read",
          "state" -> "xyz",
          "code_challenge" -> "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          "code_challenge_method" -> "S256"
        )
        revoked <- form(transport, "revocation", "token" -> access)
        afterwards <- form(transport, "introspection", "token" -> access)
      } yield {
        assertEquals(granted._1, Status.Ok)
        assertEquals(number(granted._2, "expires_in"), Some(3600L))
        assertEquals(text(granted._2, "token_type"), Some("Bearer"))
        assertEquals(introspected._1, Status.Ok)
        assertEquals(boolean(introspected._2, "active"), Some(true))
        assert(number(introspected._2, "exp").isDefined, introspected._2.noSpaces)
        assert(number(introspected._2, "iat").isDefined, introspected._2.noSpaces)
        assertEquals(device._1, Status.Ok)
        assert(number(device._2, "expires_in").isDefined, device._2.noSpaces)
        assert(number(device._2, "interval").isDefined, device._2.noSpaces)
        assertEquals(pushed._1, Status.Created)
        assert(number(pushed._2, "expires_in").isDefined, pushed._2.noSpaces)
        assertEquals(revoked._1, Status.Ok)
        assertEquals(boolean(afterwards._2, "active"), Some(false))
      }
    }
  }
}
