package dev.oauth2.server

import cats.effect.IO
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientRegistration
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Entropy
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.Scopes
import dev.oauth2.store.memory.InMemoryClientStore
import munit.CatsEffectSuite

class RegistrationServiceSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private def registration(method: ClientAuthMethod): ClientRegistration =
    ClientRegistration(Set(callback), method, unsafe(Scopes.parse("read")))

  private def setup: IO[(RegistrationService[IO], InMemoryClientStore[IO])] = {
    var calls: Int = 0
    val entropy = new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO {
        calls += 1
        Array.fill(n)(calls.toByte)
      }
    }
    InMemoryClientStore
      .create[IO](List.empty)
      .map(clients => (new RegistrationService[IO](clients, entropy), clients))
  }

  test("a confidential registration mints a client with a hashed secret") {
    for {
      pair <- setup
      (service, clients) = pair
      answered <- service.register(registration(ClientAuthMethod.ClientSecretBasic))
      response = answered.toOption.get
      stored <- clients.find(response.clientId)
    } yield {
      assert(response.secret.isDefined)
      assertEquals(stored.map(_.authMethod), Some(ClientAuthMethod.ClientSecretBasic))
      assertEquals(stored.map(_.redirectUris), Some(Set(callback)))
      assertEquals(stored.map(_.scopes), Some(unsafe(Scopes.parse("read"))))
      assertEquals(
        stored.flatMap(_.secretHash).map(hash => ClientSecretHash.verify(hash, response.secret.get)),
        Some(true)
      )
    }
  }

  test("a public registration mints a client without a secret") {
    for {
      pair <- setup
      (service, clients) = pair
      answered <- service.register(registration(ClientAuthMethod.None))
      response = answered.toOption.get
      stored <- clients.find(response.clientId)
    } yield {
      assertEquals(response.secret, None)
      assertEquals(stored.flatMap(_.secretHash), None)
    }
  }

  test("every registration mints a distinct client id") {
    for {
      pair <- setup
      (service, _) = pair
      first <- service.register(registration(ClientAuthMethod.ClientSecretBasic))
      second <- service.register(registration(ClientAuthMethod.ClientSecretBasic))
    } yield assert(first.toOption.get.clientId != second.toOption.get.clientId)
  }
}
