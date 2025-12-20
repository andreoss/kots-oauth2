package kots.oauth2.server

import cats.effect.IO
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientRegistration
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.Entropy
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.Scopes
import kots.oauth2.store.memory.InMemoryClientStore
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

  test("a client secret jwt registration keeps the secret for mac verification") {
    for {
      pair <- setup
      (service, clients) = pair
      basic <- service.register(registration(ClientAuthMethod.ClientSecretBasic))
      maced <- service.register(registration(ClientAuthMethod.ClientSecretJwt))
      hashedOnly <- clients.find(basic.toOption.get.clientId)
      kept <- clients.find(maced.toOption.get.clientId)
    } yield {
      assertEquals(hashedOnly.flatMap(_.secret), None)
      assertEquals(kept.flatMap(_.secret), maced.toOption.get.secret)
      assert(kept.flatMap(_.secret).isDefined)
    }
  }

  test("a mutual tls registration mints a client without a secret") {
    for {
      pair <- setup
      (service, clients) = pair
      answered <- service.register(registration(ClientAuthMethod.TlsClientAuth))
      selfSigned <- service.register(registration(ClientAuthMethod.SelfSignedTlsClientAuth))
      stored <- clients.find(answered.toOption.get.clientId)
    } yield {
      assertEquals(answered.toOption.get.secret, None)
      assertEquals(selfSigned.toOption.get.secret, None)
      assertEquals(stored.flatMap(_.secretHash), None)
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

  test("a registration token reads, updates and deletes its own registration") {
    for {
      pair <- setup
      (service, clients) = pair
      minted <- service.register(registration(ClientAuthMethod.ClientSecretBasic))
      response = minted.toOption.get
      token = response.registrationToken.get
      read <- service.read(response.clientId.value, Some(token.value))
      updated <- service.update(
        response.clientId.value,
        Some(token.value),
        registration(ClientAuthMethod.ClientSecretBasic).copy(scopes = unsafe(Scopes.parse("read write")))
      )
      removed <- service.remove(response.clientId.value, Some(token.value))
      afterwards <- service.read(response.clientId.value, Some(token.value))
      gone <- clients.find(response.clientId)
    } yield {
      assertEquals(read.toOption.get.registration.scopes, unsafe(Scopes.parse("read")))
      assertEquals(read.toOption.get.secret, None)
      assertEquals(read.toOption.get.registrationToken, None)
      assertEquals(updated.toOption.get.registration.scopes, unsafe(Scopes.parse("read write")))
      assertEquals(removed, Right(()))
      assertEquals(afterwards.left.toOption.map(_.code), Some("invalid_client"))
      assertEquals(gone, None)
    }
  }

  test("a wrong or missing registration token is refused") {
    for {
      pair <- setup
      (service, _) = pair
      minted <- service.register(registration(ClientAuthMethod.ClientSecretBasic))
      response = minted.toOption.get
      wrong <- service.read(response.clientId.value, Some("wrong"))
      missing <- service.read(response.clientId.value, None)
      unknown <- service.read("client-9", response.registrationToken.map(_.value))
    } yield {
      assertEquals(wrong.left.toOption.map(_.code), Some("invalid_client"))
      assertEquals(missing.left.toOption.map(_.code), Some("invalid_client"))
      assertEquals(unknown.left.toOption.map(_.code), Some("invalid_client"))
    }
  }
}
