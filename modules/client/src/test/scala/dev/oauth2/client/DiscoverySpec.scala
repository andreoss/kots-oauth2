package dev.oauth2.client

import java.time.Duration
import java.time.Instant

import cats.effect.IO
import cats.effect.kernel.Ref
import dev.oauth2.core.Clock
import dev.oauth2.core.Issuer
import dev.oauth2.core.Lifetime
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.TestClock
import dev.oauth2.jose.Fakes
import munit.CatsEffectSuite
import org.http4s.Charset
import org.http4s.HttpApp
import org.http4s.Response
import org.http4s.Status
import org.http4s.client.Client

class DiscoverySpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val issuer: Issuer = unsafe(Issuer.from("https://server.example"))

  private val ttl: Lifetime = unsafe(Lifetime.fromSeconds(300L))

  private def metadataBody: String =
    """{"issuer":"https://server.example",""" +
      """"authorization_endpoint":"https://server.example/authorize",""" +
      """"token_endpoint":"https://server.example/token",""" +
      """"jwks_uri":"https://server.example/jwks"}"""

  private def jwksBody(kid: String): String =
    s"""{"keys":[{"kid":"$kid","kty":"RSA","alg":"RS256","use":"sig",""" +
      s""""n":"${Fakes.Modulus}","e":"${Fakes.Exponent}"}]}"""

  private def transport(
      fetches: Ref[IO, Int],
      kid: Ref[IO, String],
      served: String => String = identity
  ): Client[IO] =
    Client.fromHttpApp(HttpApp[IO] { request =>
      val encoder = org.http4s.EntityEncoder.stringEncoder[IO](Charset.`UTF-8`)
      fetches.update(_ + 1) >> kid.get.map { current =>
        val body =
          if (request.uri.path.toString.contains("jwks")) jwksBody(current)
          else metadataBody
        Response[IO](Status.Ok).withEntity(served(body))(encoder)
      }
    })

  private def clockOf(test: TestClock): Clock[IO] =
    new Clock[IO] {
      def instant: IO[Instant] = IO(test.instant)
    }

  test("discovery is fetched once inside the lifetime and again after it") {
    val ticking = new TestClock(start, Duration.ofSeconds(1L))
    for {
      fetches <- Ref.of[IO, Int](0)
      kid <- Ref.of[IO, String]("key-1")
      discovery <- Discovery.create[IO](transport(fetches, kid), issuer, clockOf(ticking), ttl)
      first <- discovery.metadata
      second <- discovery.metadata
      inside <- fetches.get
      _ <- IO(ticking.advance(301L))
      _ <- discovery.metadata
      after <- fetches.get
    } yield {
      assertEquals(first.toOption.get.tokenEndpoint.value, "https://server.example/token")
      assertEquals(second.toOption.get.jwksUri.value, "https://server.example/jwks")
      assertEquals(inside, 1)
      assertEquals(after, 2)
    }
  }

  test("a published key is found and an unknown kid forces one refreshing refetch") {
    val ticking = new TestClock(start, Duration.ofSeconds(1L))
    for {
      fetches <- Ref.of[IO, Int](0)
      kid <- Ref.of[IO, String]("key-1")
      discovery <- Discovery.create[IO](transport(fetches, kid), issuer, clockOf(ticking), ttl)
      found <- discovery.key(Fakes.keyId("key-1"))
      _ <- kid.set("key-2")
      rotated <- discovery.key(Fakes.keyId("key-2"))
      missing <- discovery.key(Fakes.keyId("key-9"))
    } yield {
      assertEquals(found.toOption.map(_.kid.value), Some("key-1"))
      assertEquals(rotated.toOption.map(_.kid.value), Some("key-2"))
      assert(missing.isLeft)
    }
  }

  test("the published key set is cached as a whole") {
    val ticking = new TestClock(start, Duration.ofSeconds(1L))
    for {
      fetches <- Ref.of[IO, Int](0)
      kid <- Ref.of[IO, String]("key-1")
      discovery <- Discovery.create[IO](transport(fetches, kid), issuer, clockOf(ticking), ttl)
      first <- discovery.keys
      second <- discovery.keys
      count <- fetches.get
    } yield {
      assertEquals(first.toOption.map(_.keys.length), Some(1))
      assertEquals(second.map(_.keys.length), Right(1): Either[ParseFailure, Int])
      assertEquals(count, 2)
    }
  }

  test("a metadata document naming another issuer is refused") {
    val ticking = new TestClock(start, Duration.ofSeconds(1L))
    for {
      fetches <- Ref.of[IO, Int](0)
      kid <- Ref.of[IO, String]("key-1")
      discovery <- Discovery.create[IO](
        transport(fetches, kid, _.replace("https://server.example\"", "https://other.example\"")),
        issuer,
        clockOf(ticking),
        ttl
      )
      answered <- discovery.metadata
    } yield assert(answered.isLeft)
  }

  test("an explicit refresh forgets both caches") {
    val ticking = new TestClock(start, Duration.ofSeconds(1L))
    for {
      fetches <- Ref.of[IO, Int](0)
      kid <- Ref.of[IO, String]("key-1")
      discovery <- Discovery.create[IO](transport(fetches, kid), issuer, clockOf(ticking), ttl)
      _ <- discovery.metadata
      _ <- discovery.keys
      _ <- discovery.refresh
      _ <- discovery.metadata
      _ <- discovery.keys
      count <- fetches.get
    } yield assertEquals(count, 4)
  }
}
