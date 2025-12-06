package dev.oauth2.server

import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Clock
import dev.oauth2.core.Entropy
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.RequestUri
import dev.oauth2.core.Scopes
import dev.oauth2.store.Client
import dev.oauth2.store.memory.InMemoryPushedRequestStore
import munit.CatsEffectSuite

class PushedAuthorizationServiceSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private val registered: Client = Client(
    clientId,
    Set(callback),
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private def parameters: Map[String, String] =
    Map(
      "response_type" -> "code",
      "client_id" -> clientId.value,
      "redirect_uri" -> callback.value,
      "scope" -> "read",
      "state" -> "xyz",
      "code_challenge" -> "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      "code_challenge_method" -> "S256",
      "client_secret" -> "s3cret"
    )

  private def setup: IO[(PushedAuthorizationService[IO], InMemoryPushedRequestStore[IO])] = {
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO.pure(Start)
    }
    val entropy = new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO.pure(Array.fill(n)(7.toByte))
    }
    InMemoryPushedRequestStore
      .create[IO](clock)
      .map(pushed => (new PushedAuthorizationService[IO](pushed, clock, entropy, LifetimePolicy.defaults), pushed))
  }

  test("a pushed request is stored under a one time request uri without the credentials") {
    for {
      pair <- setup
      (service, pushed) = pair
      answered <- service.push(parameters, registered)
      response = answered.toOption.get
      stored <- pushed.consume(response.requestUri)
    } yield {
      assert(response.requestUri.value.startsWith(RequestUri.Prefix))
      assertEquals(response.expiresIn, 60L)
      assertEquals(stored.map(_.clientId), Some(clientId))
      assertEquals(stored.map(_.parameters.contains("client_secret")), Some(false))
      assertEquals(stored.flatMap(_.parameters.get("state")), Some("xyz"))
      assertEquals(stored.map(_.expiresAt), Some(Start.plusSeconds(60L)))
    }
  }

  test("a push for another client is refused") {
    for {
      pair <- setup
      (service, _) = pair
      answered <- service.push(parameters.updated("client_id", "client-2"), registered)
    } yield assertEquals(answered.left.toOption.map(_.code), Some("invalid_request"))
  }

  test("a push with an invalid authorization request is refused") {
    for {
      pair <- setup
      (service, _) = pair
      answered <- service.push(parameters - "state", registered)
    } yield assertEquals(answered.left.toOption.map(_.code), Some("invalid_request"))
  }
}
