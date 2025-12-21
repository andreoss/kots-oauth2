package kots.oauth2.server

import java.time.Instant

import cats.effect.IO
import kots.oauth2.core.Clock
import kots.oauth2.core.IntrospectionResponse
import kots.oauth2.core.OAuth2Error
import kots.oauth2.http.DeviceAuthorizationLogic
import kots.oauth2.http.DeviceAuthorizationResponse
import kots.oauth2.http.IntrospectionLogic
import kots.oauth2.http.TokenLogic
import kots.oauth2.store.memory.InMemoryRateLimiter
import munit.CatsEffectSuite

class ThrottleSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val clock: Clock[IO] = new Clock[IO] {
    def instant: IO[Instant] = IO.pure(Start)
  }

  private def limiter(limit: Int): IO[InMemoryRateLimiter[IO]] =
    InMemoryRateLimiter.create[IO](clock, limit, 60L)

  private val answered: TokenLogic[IO] = new TokenLogic[IO] {
    def apply(
        basic: Option[String],
        parameters: Map[String, String],
        proof: Option[String],
        certificate: Option[String]
    ) =
      IO.pure(Left(OAuth2Error.InvalidGrant()))
  }

  private def request(id: String): Map[String, String] =
    Map("grant_type" -> "authorization_code", "client_id" -> id)

  test("the token logic passes through until the limit and then answers the wait") {
    for {
      limited <- limiter(2).map(Throttle.token[IO](_, answered))
      first <- limited(None, request("client-1"))
      second <- limited(None, request("client-1"))
      third <- limited(None, request("client-1"))
    } yield {
      assertEquals(first, Left(OAuth2Error.InvalidGrant()))
      assertEquals(second, Left(OAuth2Error.InvalidGrant()))
      assertEquals(third, Left(OAuth2Error.RateLimited(60L)))
    }
  }

  test("clients are limited independently and a missing id shares one bucket") {
    for {
      limited <- limiter(1).map(Throttle.token[IO](_, answered))
      _ <- limited(None, request("client-1"))
      other <- limited(None, request("client-2"))
      bare <- limited(None, Map("grant_type" -> "authorization_code"))
      refused <- limited(None, Map("grant_type" -> "authorization_code"))
    } yield {
      assertEquals(other, Left(OAuth2Error.InvalidGrant()))
      assertEquals(bare, Left(OAuth2Error.InvalidGrant()))
      assertEquals(refused, Left(OAuth2Error.RateLimited(60L)))
    }
  }

  test("the introspection and device logics are limited the same way") {
    val introspection = new IntrospectionLogic[IO] {
      def apply(basic: Option[String], parameters: Map[String, String]) =
        IO.pure(Right(IntrospectionResponse.inactive))
    }
    val device = new DeviceAuthorizationLogic[IO] {
      def apply(basic: Option[String], parameters: Map[String, String]) =
        IO.pure(Left(OAuth2Error.InvalidClient()): Either[OAuth2Error, DeviceAuthorizationResponse])
    }
    for {
      limitedIntrospection <- limiter(1).map(Throttle.introspection[IO](_, introspection))
      limitedDevice <- limiter(1).map(Throttle.device[IO](_, device))
      passed <- limitedIntrospection(None, Map("client_id" -> "client-1"))
      refused <- limitedIntrospection(None, Map("client_id" -> "client-1"))
      devicePassed <- limitedDevice(None, Map("client_id" -> "client-1"))
      deviceRefused <- limitedDevice(None, Map("client_id" -> "client-1"))
    } yield {
      assertEquals(passed, Right(IntrospectionResponse.inactive))
      assertEquals(refused, Left(OAuth2Error.RateLimited(60L)))
      assertEquals(devicePassed, Left(OAuth2Error.InvalidClient()))
      assertEquals(deviceRefused, Left(OAuth2Error.RateLimited(60L)))
    }
  }
}
