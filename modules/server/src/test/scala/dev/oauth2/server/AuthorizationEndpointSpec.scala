package dev.oauth2.server

import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Clock
import dev.oauth2.core.CodeChallenge
import dev.oauth2.core.Entropy
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.http.AuthorizationRedirect
import dev.oauth2.http.Form
import dev.oauth2.store.Client
import dev.oauth2.store.ConsentRecord
import dev.oauth2.store.memory.InMemoryClientStore
import dev.oauth2.store.memory.InMemoryCodeStore
import dev.oauth2.store.memory.InMemoryConsentStore
import munit.CatsEffectSuite

class AuthorizationEndpointSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private val other: RedirectUri = unsafe(RedirectUri.from("https://client.example/other"))

  private val challenge: CodeChallenge =
    unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

  private val registered: Client = Client(
    clientId,
    Set(callback),
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private def params: Map[String, String] =
    Map(
      "response_type" -> "code",
      "client_id" -> clientId.value,
      "redirect_uri" -> callback.value,
      "scope" -> "read",
      "state" -> "xyz",
      "code_challenge" -> challenge.value,
      "code_challenge_method" -> "S256"
    )

  private def setup(consented: Boolean = true, authenticated: Boolean = true): IO[AuthorizationEndpoint[IO]] = {
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO.pure(Start)
    }
    val entropy = new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO.pure(Array.fill(n)(7.toByte))
    }
    for {
      codes <- InMemoryCodeStore.create[IO](clock)
      consents <- InMemoryConsentStore.create[IO]
      _ <- if (consented) consents.grant(ConsentRecord(clientId, subject, unsafe(Scopes.parse("read")))) else IO.unit
      login <- SessionLogin.create[IO]
      _ <- if (authenticated) login.login(subject) else IO.unit
      clients <- InMemoryClientStore.create[IO](List(registered))
    } yield new AuthorizationEndpoint[IO](
      clients,
      login,
      new AuthorizationService[IO](codes, consents, clock, entropy, LifetimePolicy.defaults)
    )
  }

  private def query(redirect: AuthorizationRedirect): Map[String, String] =
    Form.parse(redirect.location.dropWhile(_ != '?').drop(1)).toOption.get

  test("an authorized request is redirected back with the code and the state") {
    for {
      endpoint <- setup()
      answered <- endpoint(params)
    } yield {
      val redirect = answered.toOption.get
      assert(redirect.location.startsWith(callback.value + "?"))
      assert(query(redirect)("code").nonEmpty)
      assertEquals(query(redirect).get("state"), Some("xyz"))
      assertEquals(query(redirect).get("error"), None)
    }
  }

  test("an anonymous request is redirected back as access denied") {
    for {
      endpoint <- setup(authenticated = false)
      answered <- endpoint(params)
    } yield {
      val fields = query(answered.toOption.get)
      assertEquals(fields.get("error"), Some("access_denied"))
      assertEquals(fields.get("state"), Some("xyz"))
      assertEquals(fields.get("code"), None)
    }
  }

  test("a request without a recorded consent is redirected back as access denied") {
    for {
      endpoint <- setup(consented = false)
      answered <- endpoint(params)
    } yield assertEquals(query(answered.toOption.get).get("error"), Some("access_denied"))
  }

  test("an unknown client is answered directly with an error") {
    for {
      endpoint <- setup()
      answered <- endpoint(params.updated("client_id", "client-2"))
    } yield assertEquals(answered.left.toOption.map(_.code), Some("invalid_request"))
  }

  test("an unregistered redirect uri is never redirected to") {
    for {
      endpoint <- setup()
      answered <- endpoint(params.updated("redirect_uri", other.value))
    } yield assertEquals(answered.left.toOption.map(_.code), Some("invalid_request"))
  }

  test("a missing code challenge is redirected back as an invalid request") {
    for {
      endpoint <- setup()
      answered <- endpoint(params - "code_challenge" - "code_challenge_method")
    } yield {
      val fields = query(answered.toOption.get)
      assertEquals(fields.get("error"), Some("invalid_request"))
      assertEquals(fields.get("state"), Some("xyz"))
    }
  }
}
