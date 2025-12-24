package kots.oauth2.client

import cats.effect.IO
import cats.effect.kernel.Ref
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.ParseFailure
import munit.CatsEffectSuite
import org.http4s.Charset
import org.http4s.HttpApp
import org.http4s.Response
import org.http4s.Status
import org.http4s.UrlForm
import org.http4s.client.Client

class TokenClientSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val endpoint: EndpointUri = unsafe(EndpointUri.from("https://server.example/token"))

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val secret: ClientSecret = unsafe(ClientSecret.from("s3cret"))

  private val grantBody: String =
    """{"access_token":"at-1","token_type":"Bearer","expires_in":"3600","refresh_token":"rt-1","scope":"read"}"""

  private def transport(
      seen: Ref[IO, Option[(Map[String, String], Option[String])]],
      answer: Response[IO]
  ): Client[IO] =
    Client.fromHttpApp(HttpApp[IO] { request =>
      for {
        form <- request.as[UrlForm]
        fields = form.values.map { case (name, values) => name -> values.headOption.getOrElse("") }
        authorization = request.headers.headers
          .find(_.name.toString == "Authorization")
          .map(_.value)
        _ <- seen.set(Some((fields, authorization)))
      } yield answer
    })

  private def ok(body: String): Response[IO] =
    Response[IO](Status.Ok).withEntity(body)(org.http4s.EntityEncoder.stringEncoder(Charset.`UTF-8`))

  test("a client credentials request is granted and parsed") {
    for {
      seen <- Ref.of[IO, Option[(Map[String, String], Option[String])]](None)
      tokens = new TokenClient[IO](transport(seen, ok(grantBody)), endpoint)
      granted <- tokens.clientCredentials(clientId, secret, None)
      request <- seen.get
    } yield {
      val grant = granted.toOption.get
      assertEquals(grant.accessToken.value, "at-1")
      assertEquals(grant.tokenType, "Bearer")
      assertEquals(grant.expiresIn, 3600L)
      assertEquals(grant.refreshToken.map(_.value), Some("rt-1"))
      assertEquals(grant.scope.value.map(_.value), Set("read"))
      val (fields, authorization) = request.get
      assertEquals(fields.get("grant_type"), Some("client_credentials"))
      assertEquals(fields.get("client_id"), Some(clientId.value))
      assert(authorization.exists(_.startsWith("Basic ")))
    }
  }

  test("a code exchange carries the code, verifier and redirect uri") {
    for {
      seen <- Ref.of[IO, Option[(Map[String, String], Option[String])]](None)
      tokens = new TokenClient[IO](transport(seen, ok(grantBody)), endpoint)
      _ <- tokens.authorizationCode(
        unsafe(kots.oauth2.core.AuthorizationCode.from("code-1")),
        unsafe(kots.oauth2.core.CodeVerifier.from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
        Some(unsafe(kots.oauth2.core.RedirectUri.from("https://client.example/cb"))),
        clientId,
        Some(secret)
      )
      request <- seen.get
    } yield {
      val (fields, _) = request.get
      assertEquals(fields.get("grant_type"), Some("authorization_code"))
      assertEquals(fields.get("code"), Some("code-1"))
      assertEquals(fields.get("code_verifier"), Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
      assertEquals(fields.get("redirect_uri"), Some("https://client.example/cb"))
    }
  }

  test("a refresh request carries the refresh token") {
    for {
      seen <- Ref.of[IO, Option[(Map[String, String], Option[String])]](None)
      tokens = new TokenClient[IO](transport(seen, ok(grantBody)), endpoint)
      _ <- tokens.refresh(unsafe(kots.oauth2.core.RefreshToken.from("rt-0")), clientId, Some(secret))
      request <- seen.get
    } yield {
      val (fields, _) = request.get
      assertEquals(fields.get("grant_type"), Some("refresh_token"))
      assertEquals(fields.get("refresh_token"), Some("rt-0"))
    }
  }

  test("a device poll carries the device code grant") {
    for {
      seen <- Ref.of[IO, Option[(Map[String, String], Option[String])]](None)
      tokens = new TokenClient[IO](transport(seen, ok(grantBody)), endpoint)
      _ <- tokens.device(unsafe(kots.oauth2.core.DeviceCode.from("device-1")), clientId, Some(secret))
      request <- seen.get
    } yield {
      val (fields, _) = request.get
      assertEquals(fields.get("grant_type"), Some("urn:ietf:params:oauth:grant-type:device_code"))
      assertEquals(fields.get("device_code"), Some("device-1"))
      assertEquals(fields.get("client_id"), Some(clientId.value))
    }
  }

  test("a refused grant is carried back as its wire error") {
    for {
      seen <- Ref.of[IO, Option[(Map[String, String], Option[String])]](None)
      answer = Response[IO](Status.BadRequest)
        .withEntity("""{"error":"invalid_grant"}""")(org.http4s.EntityEncoder.stringEncoder(Charset.`UTF-8`))
      tokens = new TokenClient[IO](transport(seen, answer), endpoint)
      refused <- tokens.clientCredentials(clientId, secret, None)
    } yield assertEquals(refused, Left(OAuth2Error.InvalidGrant()))
  }

  test("an empty scope string reads as no scope at all") {
    val bare = """{"access_token":"at-1","token_type":"bearer","expires_in":3599,"scope":""}"""
    for {
      seen <- Ref.of[IO, Option[(Map[String, String], Option[String])]](None)
      tokens = new TokenClient[IO](transport(seen, ok(bare)), endpoint)
      granted <- tokens.clientCredentials(clientId, secret, None)
    } yield assertEquals(granted.toOption.map(_.scope), Some(kots.oauth2.core.Scopes.empty))
  }

  test("a numeric lifetime is parsed like the quoted form") {
    val numeric = """{"access_token":"at-1","token_type":"Bearer","expires_in":7200}"""
    for {
      seen <- Ref.of[IO, Option[(Map[String, String], Option[String])]](None)
      tokens = new TokenClient[IO](transport(seen, ok(numeric)), endpoint)
      granted <- tokens.clientCredentials(clientId, secret, None)
    } yield {
      assertEquals(granted.toOption.map(_.expiresIn), Some(7200L))
      assertEquals(granted.toOption.map(_.refreshToken), Some(None))
    }
  }

  test("an unreadable answer is a server error") {
    for {
      seen <- Ref.of[IO, Option[(Map[String, String], Option[String])]](None)
      tokens = new TokenClient[IO](
        transport(seen, ok("not json")),
        endpoint
      )
      refused <- tokens.clientCredentials(clientId, secret, None)
    } yield assert(refused.left.toOption.exists(_.code == "server_error"))
  }
}
