package kots.oauth2.server

import java.nio.charset.StandardCharsets
import java.util.Base64

import cats.effect.IO

import kots.oauth2.core.ClientAuthInput
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.store.Client
import kots.oauth2.store.memory.InMemoryClientStore

import munit.CatsEffectSuite

class ClientAuthenticationSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val id: ClientId = unsafe(ClientId.from("client-1"))

  private val otherId: ClientId = unsafe(ClientId.from("client-2"))

  private val secret: ClientSecret = unsafe(ClientSecret.from("s3cret"))

  private val storedHash: ClientSecretHash = ClientSecretHash.of(secret)

  private def basic(id: String, secret: String): Option[String] =
    Some(Base64.getEncoder.encodeToString(s"$id:$secret".getBytes(StandardCharsets.UTF_8)))

  private def client(
      method: ClientAuthMethod = ClientAuthMethod.ClientSecretBasic,
      hash: Option[ClientSecretHash] = Some(storedHash),
      id: ClientId = id
  ): Client =
    Client(id, Set.empty, Scopes.empty, method, hash)

  private def service(clients: List[Client]): IO[ClientAuthentication[IO]] =
    InMemoryClientStore.create[IO](clients).map(store => new RegisteredClientAuthentication[IO](store))

  private def input(
      basic: Option[String] = None,
      params: Map[String, String] = Map.empty
  ): ClientAuthInput =
    ClientAuthInput.from(basic, params).toOption.get

  private def rejection(result: Either[OAuth2Error, Client]): OAuth2Error =
    result.left.getOrElse(OAuth2Error.ServerError())

  private val Start: java.time.Instant = java.time.Instant.parse("2025-01-01T00:00:00Z")

  private def jwtClient: Client =
    Client(
      id,
      Set.empty,
      Scopes.empty,
      ClientAuthMethod.PrivateKeyJwt,
      None,
      kots.oauth2.jose.Jwks(List(kots.oauth2.jose.Fakes.signingJwk))
    )

  private def assertionService(
      clients: List[Client]
  ): IO[ClientAuthentication[IO]] = {
    val clock = new kots.oauth2.core.Clock[IO] {
      def instant: IO[java.time.Instant] = IO.pure(Start)
    }
    for {
      store <- InMemoryClientStore.create[IO](clients)
      replays <- kots.oauth2.store.memory.InMemoryReplayStore.create[IO](clock)
    } yield new RegisteredClientAuthentication[IO](
      store,
      Some(
        RegisteredClientAuthentication.Assertions(
          unsafe(kots.oauth2.core.Issuer.from("https://server.example")),
          replays,
          clock
        )
      )
    )
  }

  private def assertion(
      iss: String = "client-1",
      sub: String = "client-1",
      aud: String = "https://server.example",
      exp: java.time.Instant = Start.plusSeconds(60L),
      jti: String = "jti-1",
      key: java.security.PrivateKey = kots.oauth2.jose.Fakes.signingPair.getPrivate
  ): String = {
    val payload = io.circe.Json
      .obj(
        "iss" -> io.circe.Json.fromString(iss),
        "sub" -> io.circe.Json.fromString(sub),
        "aud" -> io.circe.Json.fromString(aud),
        "exp" -> io.circe.Json.fromLong(exp.getEpochSecond),
        "jti" -> io.circe.Json.fromString(jti)
      )
      .noSpaces
    kots.oauth2.jose.Jws
      .sign(kots.oauth2.jose.Alg.RS256, kots.oauth2.jose.Fakes.keyId("key-1"), key, payload)
      .toOption
      .get
  }

  private def assertionInput(raw: String): ClientAuthInput =
    input(
      None,
      Map("client_assertion" -> raw, "client_assertion_type" -> kots.oauth2.core.ClientAssertion.Type)
    )

  test("a private key jwt assertion authenticates the registered client") {
    val registered = jwtClient
    for {
      authentication <- assertionService(List(registered))
      result <- authentication.authenticate(assertionInput(assertion()))
    } yield assertEquals(result, Right(registered))
  }

  test("a replayed assertion is refused") {
    for {
      authentication <- assertionService(List(jwtClient))
      first <- authentication.authenticate(assertionInput(assertion()))
      second <- authentication.authenticate(assertionInput(assertion()))
    } yield {
      assert(first.isRight)
      assertEquals(rejection(second), OAuth2Error.InvalidClient())
    }
  }

  test("an assertion for another audience or an expired one is refused") {
    for {
      authentication <- assertionService(List(jwtClient))
      wrongAudience <- authentication.authenticate(assertionInput(assertion(aud = "https://other.example")))
      expired <- authentication.authenticate(assertionInput(assertion(exp = Start)))
    } yield {
      assertEquals(rejection(wrongAudience), OAuth2Error.InvalidClient())
      assertEquals(rejection(expired), OAuth2Error.InvalidClient())
    }
  }

  test("an assertion whose issuer and subject differ is refused") {
    for {
      authentication <- assertionService(List(jwtClient))
      result <- authentication.authenticate(assertionInput(assertion(iss = "client-2")))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("an assertion for a client registered with another method is refused") {
    for {
      authentication <- assertionService(List(client()))
      result <- authentication.authenticate(assertionInput(assertion()))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("an assertion signed by another key is refused") {
    val stranger = {
      val generator = java.security.KeyPairGenerator.getInstance("RSA")
      generator.initialize(2048)
      generator.generateKeyPair
    }
    for {
      authentication <- assertionService(List(jwtClient))
      result <- authentication.authenticate(assertionInput(assertion(key = stranger.getPrivate)))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("an assertion combined with a secret is refused") {
    for {
      authentication <- assertionService(List(jwtClient))
      result <- authentication.authenticate(
        ClientAuthInput(
          None,
          None,
          Some(secret),
          Some(unsafe(kots.oauth2.core.ClientAssertion.from(assertion())))
        )
      )
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("an assertion without a configured verifier is refused") {
    for {
      authentication <- service(List(jwtClient))
      result <- authentication.authenticate(assertionInput(assertion()))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  private def macClient(stored: Option[ClientSecret] = Some(secret)): Client =
    Client(id, Set.empty, Scopes.empty, ClientAuthMethod.ClientSecretJwt, Some(storedHash), secret = stored)

  private def macAssertion(
      key: ClientSecret = secret,
      jti: String = "jti-1"
  ): String = {
    val payload = io.circe.Json
      .obj(
        "iss" -> io.circe.Json.fromString(id.value),
        "sub" -> io.circe.Json.fromString(id.value),
        "aud" -> io.circe.Json.fromString("https://server.example"),
        "exp" -> io.circe.Json.fromLong(Start.plusSeconds(60L).getEpochSecond),
        "jti" -> io.circe.Json.fromString(jti)
      )
      .noSpaces
    kots.oauth2.jose.Hs256.sign(key, payload)
  }

  test("a client secret jwt assertion authenticates the registered client") {
    val registered = macClient()
    for {
      authentication <- assertionService(List(registered))
      result <- authentication.authenticate(assertionInput(macAssertion()))
    } yield assertEquals(result, Right(registered))
  }

  test("a client secret jwt assertion maced with another secret is refused") {
    for {
      authentication <- assertionService(List(macClient()))
      result <- authentication.authenticate(
        assertionInput(macAssertion(key = unsafe(ClientSecret.from("other"))))
      )
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("a client secret jwt assertion without a kept secret is refused") {
    for {
      authentication <- assertionService(List(macClient(stored = None)))
      result <- authentication.authenticate(assertionInput(macAssertion()))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("a replayed client secret jwt assertion is refused") {
    for {
      authentication <- assertionService(List(macClient()))
      first <- authentication.authenticate(assertionInput(macAssertion()))
      second <- authentication.authenticate(assertionInput(macAssertion()))
    } yield {
      assert(first.isRight)
      assertEquals(rejection(second), OAuth2Error.InvalidClient())
    }
  }

  test("basic credentials authenticate a client registered for client_secret_basic") {
    val registered = client()
    for {
      authentication <- service(List(registered))
      result <- authentication.authenticate(input(basic("client-1", "s3cret")))
    } yield assertEquals(result, Right(registered))
  }

  test("body credentials authenticate a client registered for client_secret_post") {
    val registered = client(ClientAuthMethod.ClientSecretPost)
    for {
      authentication <- service(List(registered))
      result <- authentication.authenticate(
        input(None, Map("client_id" -> "client-1", "client_secret" -> "s3cret"))
      )
    } yield assertEquals(result, Right(registered))
  }

  test("basic credentials are refused for a client registered for client_secret_post") {
    for {
      authentication <- service(List(client(ClientAuthMethod.ClientSecretPost)))
      result <- authentication.authenticate(input(basic("client-1", "s3cret")))
    } yield assert(result.isLeft)
  }

  test("body credentials are refused for a client registered for client_secret_basic") {
    for {
      authentication <- service(List(client()))
      result <- authentication.authenticate(
        input(None, Map("client_id" -> "client-1", "client_secret" -> "s3cret"))
      )
    } yield assert(result.isLeft)
  }

  test("a wrong secret is refused as invalid_client without a description") {
    for {
      authentication <- service(List(client()))
      result <- authentication.authenticate(input(basic("client-1", "wrong")))
    } yield {
      assertEquals(rejection(result), OAuth2Error.InvalidClient())
      assertEquals(rejection(result).body, Map("error" -> "invalid_client"))
      assert(rejection(result).challenge.isDefined)
    }
  }

  test("an unknown client is refused") {
    for {
      authentication <- service(List.empty)
      result <- authentication.authenticate(input(basic("client-1", "s3cret")))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("a confidential client without credentials is refused") {
    for {
      authentication <- service(List(client()))
      result <- authentication.authenticate(input(None, Map("client_id" -> "client-1")))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("a public client authenticates with none") {
    val registered = client(ClientAuthMethod.None, None)
    for {
      authentication <- service(List(registered))
      result <- authentication.authenticate(input(None, Map("client_id" -> "client-1")))
    } yield assertEquals(result, Right(registered))
  }

  test("a public client is not confidential") {
    assertEquals(client(ClientAuthMethod.None, None).confidential, false)
    assertEquals(client().confidential, true)
  }

  test("a public client sending a secret is refused") {
    for {
      authentication <- service(List(client(ClientAuthMethod.None, None)))
      result <- authentication.authenticate(
        input(None, Map("client_id" -> "client-1", "client_secret" -> "s3cret"))
      )
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("basic credentials for another client than the body client id are refused") {
    for {
      authentication <- service(List(client(), client(id = otherId)))
      result <- authentication.authenticate(
        input(basic("client-1", "s3cret"), Map("client_id" -> "client-2"))
      )
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("credentials without a client id are refused") {
    for {
      authentication <- service(List(client()))
      result <- authentication.authenticate(input())
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("a client registered without a secret hash is refused") {
    for {
      authentication <- service(List(client(hash = None)))
      result <- authentication.authenticate(input(basic("client-1", "s3cret")))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("every failure answers the same error") {
    val registered = client()
    for {
      authentication <- service(List(registered))
      unknown <- authentication.authenticate(input(basic("client-2", "s3cret")))
      wrong <- authentication.authenticate(input(basic("client-1", "wrong")))
      missing <- authentication.authenticate(input(None, Map("client_id" -> "client-1")))
    } yield {
      assertEquals(rejection(unknown), OAuth2Error.InvalidClient())
      assertEquals(rejection(wrong), OAuth2Error.InvalidClient())
      assertEquals(rejection(missing), OAuth2Error.InvalidClient())
    }
  }
}
