package dev.oauth2.server

import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Clock
import dev.oauth2.core.DeviceAuthorizationRequest
import dev.oauth2.core.EndpointUri
import dev.oauth2.core.Entropy
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Scopes
import dev.oauth2.store.Client
import dev.oauth2.store.memory.InMemoryDeviceStore
import munit.CatsEffectSuite

class DeviceAuthorizationServiceSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val verification: EndpointUri = unsafe(EndpointUri.from("https://server.example/device"))

  private val client: Client = Client(
    clientId,
    Set.empty,
    unsafe(Scopes.parse("read write")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private def setup: IO[(DeviceAuthorizationService[IO], InMemoryDeviceStore[IO])] = {
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
    InMemoryDeviceStore
      .create[IO](clock)
      .map(devices =>
        (new DeviceAuthorizationService[IO](devices, clock, entropy, LifetimePolicy.defaults, verification), devices)
      )
  }

  private def request(scope: Option[String]): DeviceAuthorizationRequest =
    DeviceAuthorizationRequest(scope.map(raw => unsafe(Scopes.parse(raw))), clientId)

  test("an authorization mints the codes and saves the record") {
    for {
      pair <- setup
      (service, devices) = pair
      answered <- service.authorize(request(Some("read")), client)
      response = answered.toOption.get
      stored <- devices.poll(response.deviceCode)
    } yield {
      assertEquals(response.userCode.value, "DDDD-DDDD")
      assertEquals(response.verificationUri, verification)
      assertEquals(response.expiresIn, 1800L)
      assertEquals(response.interval, DeviceAuthorizationService.Interval.seconds)
      assertEquals(stored.map(_.userCode), Some(response.userCode))
      assertEquals(stored.map(_.scopes), Some(unsafe(Scopes.parse("read"))))
      assertEquals(stored.map(_.expiresAt), Some(Start.plusSeconds(1800L)))
      assertEquals(stored.flatMap(_.subject), None)
    }
  }

  test("a user code is drawn from the unambiguous alphabet") {
    val code = DeviceAuthorizationService.userCode(Array.range(0, 8).map(_.toByte))
    assertEquals(code.length, 9)
    assertEquals(code(4), '-')
    assert(code.filterNot(_ == '-').forall(DeviceAuthorizationService.Alphabet.contains(_)))
  }

  test("a request without a scope falls back to the client scopes") {
    for {
      pair <- setup
      (service, devices) = pair
      answered <- service.authorize(request(None), client)
      stored <- devices.poll(answered.toOption.get.deviceCode)
    } yield assertEquals(stored.map(_.scopes), Some(client.scopes))
  }

  test("the requested resource is recorded on the device authorization") {
    val bound = unsafe(dev.oauth2.core.ResourceIndicator.from("https://api.example"))
    for {
      pair <- setup
      (service, devices) = pair
      answered <- service.authorize(request(None).copy(resource = Some(bound)), client)
      stored <- devices.poll(answered.toOption.get.deviceCode)
    } yield assertEquals(stored.flatMap(_.resource), Some(bound))
  }

  test("a scope outside the client registration is refused") {
    for {
      pair <- setup
      (service, _) = pair
      answered <- service.authorize(request(Some("admin")), client)
    } yield assertEquals(answered.left.toOption.map(_.code), Some("invalid_scope"))
  }
}
