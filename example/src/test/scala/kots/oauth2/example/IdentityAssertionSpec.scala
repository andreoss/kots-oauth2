package kots.oauth2.example

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.time.Instant
import java.util.Base64

import scala.concurrent.duration._

import cats.effect.IO
import cats.effect.kernel.Resource
import com.comcast.ip4s.{Port => NetworkPort}
import kots.oauth2.core.ParseFailure
import kots.oauth2.host.Development
import kots.oauth2.host.DiscoveredIssuers
import munit.CatsEffectSuite
import org.http4s.BasicCredentials
import org.http4s.Method
import org.http4s.Request
import org.http4s.Status
import org.http4s.Uri
import org.http4s.UrlForm
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.Authorization

class IdentityAssertionSpec extends CatsEffectSuite {

  override def munitIOTimeout: Duration = 5.minutes

  private val ProviderPort: Int = 28090

  private val ProviderIssuer: String = s"http://localhost:$ProviderPort"

  private val AssertionKeyId: String = "idp-key"

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(failure => sys.error(failure.toString), identity)

  private val pair: java.security.KeyPair = {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator.generateKeyPair
  }

  private val published: kots.oauth2.jose.Jwk = {
    val public = pair.getPublic.asInstanceOf[java.security.interfaces.RSAPublicKey]
    def parameter(value: java.math.BigInteger): String =
      Base64.getUrlEncoder.withoutPadding.encodeToString(value.toByteArray.dropWhile(_ == 0))
    unsafe(
      kots.oauth2.jose.Jwk.rsa(
        unsafe(kots.oauth2.core.KeyId.from(AssertionKeyId)),
        kots.oauth2.jose.Alg.RS256,
        parameter(public.getModulus),
        parameter(public.getPublicExponent)
      )
    )
  }

  private def documents: Resource[IO, Path] =
    Resource.make(IO.blocking {
      val root = Files.createTempDirectory("identity-provider")
      val wellKnown = Files.createDirectories(root.resolve(".well-known"))
      val metadata =
        s"""{"issuer":"$ProviderIssuer","authorization_endpoint":"$ProviderIssuer/authorize",""" +
          s""""token_endpoint":"$ProviderIssuer/token","jwks_uri":"$ProviderIssuer/jwks.json"}"""
      val keys = io.circe.Json
        .fromFields(kots.oauth2.http.JwkSet.render(kots.oauth2.jose.Jwks(List(published))))
        .noSpaces
      Files.write(wellKnown.resolve("oauth-authorization-server"), metadata.getBytes("UTF-8"))
      Files.write(root.resolve("jwks.json"), keys.getBytes("UTF-8"))
      root
    })(root =>
      IO.blocking {
        Files.walk(root).sorted(java.util.Comparator.reverseOrder()).forEach(path => Files.delete(path))
      }.attempt.void
    )

  private def provider(root: Path): Resource[IO, String] =
    Containers.container(
      List(
        "-p",
        s"$ProviderPort:8000",
        "-v",
        s"$root:/srv:ro,z",
        "-w",
        "/srv",
        "docker.io/library/python:3-alpine",
        "python",
        "-m",
        "http.server",
        "8000"
      )
    )

  private def assertion(
      jti: String,
      now: Instant,
      audience: String = Development.SeedIssuer,
      typ: String = kots.oauth2.jose.Jwt.IdentityAssertionTyp
  ): String = {
    val claims = kots.oauth2.jose.JwtClaims(
      issuer = unsafe(kots.oauth2.core.Issuer.from(ProviderIssuer)),
      subject = unsafe(kots.oauth2.core.Subject.from("assertion-user")),
      audience = List(unsafe(kots.oauth2.core.Audience.from(audience))),
      clientId = unsafe(kots.oauth2.core.ClientId.from(Development.SeedClientId)),
      scopes = unsafe(kots.oauth2.core.Scopes.parse("read")),
      issuedAt = now,
      expiresAt = now.plusSeconds(300L),
      tokenId = unsafe(kots.oauth2.core.JwtId.from(jti))
    )
    kots.oauth2.jose.Jws
      .sign(
        kots.oauth2.jose.Alg.RS256,
        unsafe(kots.oauth2.core.KeyId.from(AssertionKeyId)),
        pair.getPrivate,
        kots.oauth2.jose.Jwt.render(claims),
        typ
      )
      .toOption
      .get
  }

  private def exchange(transport: Client[IO], base: String, compact: String): IO[(Status, String)] =
    transport
      .run(
        Request[IO](
          method = Method.POST,
          uri = Uri.unsafeFromString(s"$base/token"),
          headers = org.http4s.Headers(
            Authorization(BasicCredentials(Development.SeedClientId, Development.SeedClientSecret))
          )
        ).withEntity(
          UrlForm(
            "grant_type" -> kots.oauth2.core.GrantType.IdJag.value,
            "assertion" -> compact,
            "client_id" -> Development.SeedClientId
          )
        )
      )
      .use(response => response.bodyText.compile.string.map(response.status -> _))

  test("an assertion from a live identity provider is exchanged for an access token") {
    assume(Containers.enabled, "the container runtime is not available or e2e is not enabled")
    val clock = new kots.oauth2.core.Clock[IO] {
      def instant: IO[Instant] = IO.realTimeInstant
    }
    val stack = for {
      root <- documents
      _ <- provider(root)
      transport <- EmberClientBuilder.default[IO].build
      issuers <- Resource.eval(
        DiscoveredIssuers
          .create[IO](transport, clock, List(unsafe(kots.oauth2.core.Issuer.from(ProviderIssuer))))
      )
      server <- Development.server[IO](NetworkPort.fromInt(0).get, Some(issuers))
    } yield (transport, server)
    stack.use { case (transport, server) =>
      val base = s"http://localhost:${server.address.getPort}"
      for {
        _ <- Containers.awaitHttp(transport, s"$ProviderIssuer/jwks.json")
        now <- clock.instant
        granted <- exchange(transport, base, assertion("live-1", now))
        replayed <- exchange(transport, base, assertion("live-1", now))
        foreign <- exchange(transport, base, assertion("live-2", now, audience = "https://other.example"))
        confused <- exchange(
          transport,
          base,
          assertion("live-3", now, typ = kots.oauth2.jose.Jwt.AccessTokenType)
        )
      } yield {
        assert(granted._2.contains("access_token"), s"${granted._1}: ${granted._2}")
        assertEquals(granted._1, Status.Ok)
        assert(!granted._2.contains("refresh_token"), granted._2)
        assertEquals(replayed._1, Status.BadRequest)
        assert(replayed._2.contains("invalid_grant"), replayed._2)
        assertEquals(foreign._1, Status.BadRequest)
        assertEquals(confused._1, Status.BadRequest)
      }
    }
  }
}
