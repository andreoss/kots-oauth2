package dev.oauth2.server

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

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
import dev.oauth2.http.TokenResponse
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.memory.InMemoryClientStore
import dev.oauth2.store.memory.InMemoryCodeStore
import dev.oauth2.store.memory.InMemoryGrantStore
import dev.oauth2.store.memory.InMemoryTokenStore
import munit.CatsEffectSuite

class TokenEndpointSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private val verifier: CodeVerifier =
    unsafe(CodeVerifier.from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))

  private val challenge: CodeChallenge =
    unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

  private val pkce: Pkce = Pkce(challenge, CodeChallengeMethod.S256)

  private val refused: String = "a" * 42 + "!"

  private def record(name: String): CodeRecord =
    CodeRecord(
      code = unsafe(AuthorizationCode.from(name)),
      clientId = clientId,
      redirectUri = callback,
      subject = subject,
      scopes = unsafe(Scopes.parse("read")),
      details = AuthorizationDetails.empty,
      pkce = Some(pkce),
      expiresAt = Start.plusSeconds(60L)
    )

  private def client(method: ClientAuthMethod = ClientAuthMethod.ClientSecretBasic): Client =
    Client(
      clientId,
      Set(callback),
      unsafe(Scopes.parse("read")),
      method,
      if (method == ClientAuthMethod.None) None else Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
    )

  private def basic(id: String, secret: String): Option[String] =
    Some(Base64.getEncoder.encodeToString(s"$id:$secret".getBytes(StandardCharsets.UTF_8)))

  private def codeParams(code: String, raw: String = verifier.value): Map[String, String] =
    Map(
      "grant_type" -> "authorization_code",
      "code" -> code,
      "code_verifier" -> raw,
      "client_id" -> clientId.value
    )

  private def refreshParams(token: String): Map[String, String] =
    Map("grant_type" -> "refresh_token", "refresh_token" -> token, "client_id" -> clientId.value)

  private def setup(
      stored: Option[CodeRecord] = Some(record("code-1")),
      clients: List[Client] = List(client())
  ): IO[TokenEndpoint[IO]] = {
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
      _ <- stored.fold(IO.unit)(codes.save)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
      registry <- InMemoryClientStore.create[IO](clients)
    } yield new TokenEndpoint[IO](
      new RegisteredClientAuthentication[IO](registry),
      new TokenService[IO](codes, tokens, grants, clock, entropy, LifetimePolicy.defaults)
    )
  }

  private def code(result: Either[OAuth2Error, TokenResponse]): Option[String] =
    result.left.toOption.map(_.code)

  test("an authorization code request is answered with a token response") {
    for {
      endpoint <- setup()
      result <- endpoint(basic("client-1", "s3cret"), codeParams("code-1"))
    } yield {
      val response = result.toOption.get
      assert(response.accessToken.value.nonEmpty)
      assertEquals(response.expiresIn, 3600L)
      assertEquals(response.scope, unsafe(Scopes.parse("read")))
      assert(response.refreshToken.isDefined)
    }
  }

  test("a refresh request is answered with a rotated token response") {
    for {
      endpoint <- setup()
      first <- endpoint(basic("client-1", "s3cret"), codeParams("code-1"))
      rotated = first.toOption.get.refreshToken.get.value
      second <- endpoint(basic("client-1", "s3cret"), refreshParams(rotated))
      reused <- endpoint(basic("client-1", "s3cret"), refreshParams(rotated))
    } yield {
      assertNotEquals(second.toOption.map(_.accessToken.value), first.toOption.map(_.accessToken.value))
      assert(second.toOption.flatMap(_.refreshToken).isDefined)
      assertEquals(code(reused), Some("invalid_grant"))
    }
  }

  test("a client credentials request is answered without a refresh token") {
    for {
      endpoint <- setup()
      result <- endpoint(
        basic("client-1", "s3cret"),
        Map("grant_type" -> "client_credentials", "scope" -> "read", "client_id" -> clientId.value)
      )
    } yield {
      val response = result.toOption.get
      assert(response.accessToken.value.nonEmpty)
      assertEquals(response.refreshToken, None)
      assertEquals(response.scope, unsafe(Scopes.parse("read")))
    }
  }

  test("a client credentials request with an unregistered scope is refused") {
    for {
      endpoint <- setup()
      result <- endpoint(
        basic("client-1", "s3cret"),
        Map("grant_type" -> "client_credentials", "scope" -> "read write", "client_id" -> clientId.value)
      )
    } yield assertEquals(code(result), Some("invalid_scope"))
  }

  test("an unregistered client is refused with invalid_client") {
    for {
      endpoint <- setup(clients = Nil)
      result <- endpoint(basic("client-1", "s3cret"), codeParams("code-1"))
    } yield assertEquals(code(result), Some("invalid_client"))
  }

  test("a wrong secret is refused without a description") {
    for {
      endpoint <- setup()
      result <- endpoint(basic("client-1", "wrong"), codeParams("code-1"))
    } yield {
      assertEquals(code(result), Some("invalid_client"))
      assertEquals(result.left.toOption.flatMap(_.description), None)
    }
  }

  test("a public client is answered without a refresh token") {
    for {
      endpoint <- setup(clients = List(client(ClientAuthMethod.None)))
      result <- endpoint(None, codeParams("code-1"))
    } yield {
      assert(result.isRight)
      assertEquals(result.toOption.flatMap(_.refreshToken), None)
    }
  }

  test("a request without a grant type is refused with invalid_request") {
    for {
      endpoint <- setup()
      result <- endpoint(basic("client-1", "s3cret"), Map("code" -> "code-1", "client_id" -> clientId.value))
    } yield assertEquals(code(result), Some("invalid_request"))
  }

  test("an unknown grant type is refused with unsupported_grant_type") {
    for {
      endpoint <- setup()
      result <- endpoint(basic("client-1", "s3cret"), Map("grant_type" -> "password", "client_id" -> clientId.value))
    } yield assertEquals(code(result), Some("unsupported_grant_type"))
  }

  test("a malformed code verifier is refused with invalid_request") {
    for {
      endpoint <- setup()
      result <- endpoint(basic("client-1", "s3cret"), codeParams("code-1", refused))
    } yield assertEquals(code(result), Some("invalid_request"))
  }

  test("a replayed code is refused with invalid_grant") {
    for {
      endpoint <- setup()
      first <- endpoint(basic("client-1", "s3cret"), codeParams("code-1"))
      second <- endpoint(basic("client-1", "s3cret"), codeParams("code-1"))
    } yield {
      assert(first.isRight)
      assertEquals(code(second), Some("invalid_grant"))
    }
  }

  test("a body client id that disagrees with the credentials is refused") {
    for {
      endpoint <- setup()
      result <- endpoint(basic("client-1", "s3cret"), codeParams("code-1").updated("client_id", "client-2"))
    } yield assertEquals(code(result), Some("invalid_client"))
  }
}
