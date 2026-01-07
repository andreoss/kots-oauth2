package dev.oauth2.host

import java.nio.charset.StandardCharsets
import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Clock
import dev.oauth2.core.CodeChallenge
import dev.oauth2.core.CodeChallengeMethod
import dev.oauth2.core.CodeVerifier
import dev.oauth2.core.Entropy
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.http.Endpoints
import dev.oauth2.http.Form
import dev.oauth2.http.Server
import dev.oauth2.server.IntrospectionEndpoint
import dev.oauth2.server.RegisteredClientAuthentication
import dev.oauth2.server.RevocationEndpoint
import dev.oauth2.server.TokenEndpoint
import dev.oauth2.server.TokenService
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.memory.InMemoryClientStore
import dev.oauth2.store.memory.InMemoryCodeStore
import dev.oauth2.store.memory.InMemoryGrantStore
import dev.oauth2.store.memory.InMemoryTokenStore
import fs2.Stream
import munit.CatsEffectSuite
import org.http4s.BasicCredentials
import org.http4s.Header
import org.http4s.Headers
import org.http4s.MediaType
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.Uri
import org.http4s.headers.Authorization
import org.http4s.headers.`Content-Type`
import org.typelevel.ci.CIString

class InterpreterSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val verifier: CodeVerifier =
    unsafe(CodeVerifier.from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))

  private val challenge: CodeChallenge =
    unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

  private val recorded: CodeRecord = CodeRecord(
    code = unsafe(AuthorizationCode.from("code-1")),
    clientId = clientId,
    redirectUri = unsafe(RedirectUri.from("https://client.example/cb")),
    subject = unsafe(Subject.from("user-1")),
    scopes = unsafe(Scopes.parse("read")),
    details = AuthorizationDetails.empty,
    pkce = Some(Pkce(challenge, CodeChallengeMethod.S256)),
    expiresAt = Start.plusSeconds(60L)
  )

  private val registered: Client = Client(
    clientId,
    Set(unsafe(RedirectUri.from("https://client.example/cb"))),
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private def post(form: Map[String, String], secret: Option[String]): Request[IO] =
    postTo("/token", form, secret)

  private def postTo(
      path: String,
      form: Map[String, String],
      secret: Option[String]
  ): Request[IO] =
    Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString(s"http://localhost$path"),
      headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
        Headers(secret.toList.map(value => Authorization(BasicCredentials(clientId.value, value)))),
      body = Stream.emits(Form.render(form).getBytes(StandardCharsets.UTF_8).toSeq).covary[IO]
    )

  private def routes: IO[org.http4s.HttpRoutes[IO]] = {
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO.pure(Start)
    }
    var calls: Int = 0
    val entropy = new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO {
        calls += 1
        Array.fill(n)(calls.toByte)
      }
    }
    for {
      codes <- InMemoryCodeStore.create[IO](clock)
      _ <- codes.save(recorded)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
      clients <- InMemoryClientStore.create[IO](List(registered))
      revocation = new RevocationEndpoint[IO](new RegisteredClientAuthentication[IO](clients), tokens, grants)
      introspection = new IntrospectionEndpoint[IO](new RegisteredClientAuthentication[IO](clients), tokens, grants)
    } yield Interpreter.routes[IO](
      List(
        Server.token(
          new TokenEndpoint[IO](
            new RegisteredClientAuthentication[IO](clients),
            new TokenService[IO](codes, tokens, grants, clock, entropy, LifetimePolicy.defaults)
          )
        ),
        Server.revocation(revocation),
        Server.introspection(introspection)
      )
    )
  }

  private def cacheControl(response: Response[IO]): Option[String] =
    response.headers.headers.find(_.name.toString == Endpoints.CacheControlHeader).map(_.value)

  private def body(response: Response[IO]): IO[String] =
    response.body.compile.toVector.map(bytes => new String(bytes.toArray, StandardCharsets.UTF_8))

  private def field(text: String, name: String): String =
    io.circe.parser
      .parse(text)
      .toOption
      .flatMap(_.hcursor.get[String](name).toOption)
      .getOrElse(sys.error(s"no $name in $text"))

  private def revoke(token: String, hint: String): Map[String, String] =
    Map("token" -> token, "token_type_hint" -> hint)

  private val exchange: Map[String, String] = Map(
    "grant_type" -> "authorization_code",
    "code" -> "code-1",
    "code_verifier" -> verifier.value,
    "client_id" -> clientId.value
  )

  test("a form post to the token endpoint is answered with a token") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Ok)
      assert(text.contains("access_token"))
      assert(text.contains("refresh_token"))
    }
  }

  test("a form post with a wrong secret is answered with unauthorized") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("wrong"))).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Unauthorized)
      assert(text.contains("invalid_client"))
    }
  }

  test("a refused client is answered with the challenge of the error model") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("wrong"))).value
      response = answered.get
    } yield assertEquals(
      response.headers.headers.find(_.name.toString == "WWW-Authenticate").map(_.value),
      Some(OAuth2Error.BasicChallenge)
    )
  }

  test("a malformed basic header is answered with unauthorized and the challenge") {
    for {
      served <- routes
      answered <- served
        .run(
          post(exchange, None).putHeaders(
            Header.Raw(CIString("Authorization"), "Basic not base64 !")
          )
        )
        .value
      response = answered.get
    } yield {
      assertEquals(response.status, Status.Unauthorized)
      assertEquals(
        response.headers.headers.find(_.name.toString == "WWW-Authenticate").map(_.value),
        Some(OAuth2Error.BasicChallenge)
      )
    }
  }

  test("a replayed code is answered with bad request") {
    for {
      served <- routes
      first <- served.run(post(exchange, Some("s3cret"))).value
      second <- served.run(post(exchange, Some("s3cret"))).value
      text <- body(second.get)
    } yield {
      assertEquals(first.get.status, Status.Ok)
      assertEquals(second.get.status, Status.BadRequest)
      assert(text.contains("invalid_grant"))
    }
  }

  test("an answered token is served with cache control no-store") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      response = answered.get
    } yield assertEquals(cacheControl(response), Some(Endpoints.NoStore))
  }

  test("a refused token is served with cache control no-store") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("wrong"))).value
      response = answered.get
    } yield assertEquals(cacheControl(response), Some(Endpoints.NoStore))
  }

  test("a revoked refresh token is answered with an empty success and refused afterwards") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      refresh <- body(answered.get).map(field(_, "refresh_token"))
      revoked <- served.run(postTo("/revocation", revoke(refresh, "refresh_token"), Some("s3cret"))).value
      text <- body(revoked.get)
      reused <- served
        .run(post(Map("grant_type" -> "refresh_token", "refresh_token" -> refresh, "client_id" -> clientId.value), Some("s3cret")))
        .value
      refused <- body(reused.get)
    } yield {
      assertEquals(revoked.get.status, Status.Ok)
      assertEquals(text, "")
      assertEquals(reused.get.status, Status.BadRequest)
      assert(refused.contains("invalid_grant"))
    }
  }

  test("an unknown token is revoked with an empty success") {
    for {
      served <- routes
      answered <- served.run(postTo("/revocation", revoke("absent", "access_token"), Some("s3cret"))).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.Ok)
      assertEquals(text, "")
    }
  }

  test("revoking an access token invalidates the pair it was issued with") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      text <- body(answered.get)
      access = field(text, "access_token")
      refresh = field(text, "refresh_token")
      revoked <- served.run(postTo("/revocation", revoke(access, "access_token"), Some("s3cret"))).value
      reused <- served
        .run(post(Map("grant_type" -> "refresh_token", "refresh_token" -> refresh, "client_id" -> clientId.value), Some("s3cret")))
        .value
    } yield {
      assertEquals(revoked.get.status, Status.Ok)
      assertEquals(reused.get.status, Status.BadRequest)
    }
  }

  test("revocation with a wrong secret is answered with unauthorized") {
    for {
      served <- routes
      answered <- served.run(postTo("/revocation", revoke("at-1", "access_token"), Some("wrong"))).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.Unauthorized)
      assert(text.contains("invalid_client"))
    }
  }

  test("a revoked token is served with cache control no-store") {
    for {
      served <- routes
      answered <- served.run(postTo("/revocation", revoke("absent", "access_token"), Some("s3cret"))).value
    } yield assertEquals(cacheControl(answered.get), Some(Endpoints.NoStore))
  }

  test("an issued access token is introspected as active with its metadata") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      issued <- body(answered.get).map(field(_, "access_token"))
      introspected <- served.run(postTo("/introspection", revoke(issued, "access_token"), Some("s3cret"))).value
      response = introspected.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Ok)
      assertEquals(field(text, "active"), "true")
      assertEquals(field(text, "client_id"), clientId.value)
      assertEquals(field(text, "scope"), "read")
      assertEquals(field(text, "token_type"), "Bearer")
    }
  }

  test("an unknown token is introspected as inactive") {
    for {
      served <- routes
      answered <- served.run(postTo("/introspection", revoke("absent", "access_token"), Some("s3cret"))).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Ok)
      assertEquals(field(text, "active"), "false")
      assert(!text.contains("client_id"))
    }
  }

  test("a revoked token is introspected as inactive") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      refresh <- body(answered.get).map(field(_, "refresh_token"))
      _ <- served.run(postTo("/revocation", revoke(refresh, "refresh_token"), Some("s3cret"))).value
      introspected <- served.run(postTo("/introspection", revoke(refresh, "refresh_token"), Some("s3cret"))).value
      text <- body(introspected.get)
    } yield assertEquals(field(text, "active"), "false")
  }

  test("introspection without credentials is answered with unauthorized") {
    for {
      served <- routes
      answered <- served.run(postTo("/introspection", revoke("at-1", "access_token"), None)).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Unauthorized)
      assert(text.contains("invalid_client"))
    }
  }

  test("an introspection answer is served with cache control no-store") {
    for {
      served <- routes
      answered <- served.run(postTo("/introspection", revoke("absent", "access_token"), Some("s3cret"))).value
    } yield assertEquals(cacheControl(answered.get), Some(Endpoints.NoStore))
  }

  test("a request to another path is not served") {
    for {
      served <- routes
      answered <- served.run(Request[IO](method = Method.GET, uri = Uri.unsafeFromString("http://localhost/other"))).value
    } yield assertEquals(answered, None)
  }
}
