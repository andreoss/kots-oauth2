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
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.http.Form
import dev.oauth2.http.Server
import dev.oauth2.server.RegisteredClientAuthentication
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
import org.http4s.Headers
import org.http4s.MediaType
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.Uri
import org.http4s.headers.Authorization
import org.http4s.headers.`Content-Type`

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
    Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString("http://localhost/token"),
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
    } yield Interpreter.routes[IO](
      List(
        Server.token(
          new TokenEndpoint[IO](
            new RegisteredClientAuthentication[IO](clients),
            new TokenService[IO](codes, tokens, grants, clock, entropy, LifetimePolicy.defaults)
          )
        )
      )
    )
  }

  private def body(response: Response[IO]): IO[String] =
    response.body.compile.toVector.map(bytes => new String(bytes.toArray, StandardCharsets.UTF_8))

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

  test("a request to another path is not served") {
    for {
      served <- routes
      answered <- served.run(Request[IO](method = Method.GET, uri = Uri.unsafeFromString("http://localhost/other"))).value
    } yield assertEquals(answered, None)
  }
}
