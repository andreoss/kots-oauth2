package kots.oauth2.host

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.util.Base64

import cats.effect.Async
import cats.effect.Resource
import cats.effect.implicits._
import cats.syntax.flatMap._
import cats.syntax.functor._
import com.comcast.ip4s.Port

import kots.oauth2.core.AuthorizationServerMetadata
import kots.oauth2.core.Clock
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.Entropy
import kots.oauth2.core.Issuer
import kots.oauth2.core.LifetimePolicy
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.ProtectedResourceMetadata
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.http.Server
import kots.oauth2.jose.Alg
import kots.oauth2.jose.Jwk
import kots.oauth2.jose.SigningKey
import kots.oauth2.server.AuthorizationEndpoint
import kots.oauth2.server.AuthorizationService
import kots.oauth2.server.DeviceAuthorizationEndpoint
import kots.oauth2.server.DeviceAuthorizationService
import kots.oauth2.server.IntrospectionEndpoint
import kots.oauth2.server.PushedAuthorizationEndpoint
import kots.oauth2.server.PushedAuthorizationService
import kots.oauth2.server.RegisteredClientAuthentication
import kots.oauth2.server.RegistrationEndpoint
import kots.oauth2.server.RegistrationService
import kots.oauth2.server.RevocationEndpoint
import kots.oauth2.server.SessionLogin
import kots.oauth2.server.TokenEndpoint
import kots.oauth2.server.TokenService
import kots.oauth2.store.Client
import kots.oauth2.store.ConsentRecord
import kots.oauth2.store.memory.InMemoryClientStore
import kots.oauth2.store.memory.InMemoryCodeStore
import kots.oauth2.store.memory.InMemoryConsentStore
import kots.oauth2.store.memory.InMemoryDeviceStore
import kots.oauth2.store.memory.InMemoryGrantStore
import kots.oauth2.store.memory.InMemoryKeyStore
import kots.oauth2.store.memory.InMemoryMetrics
import kots.oauth2.store.memory.InMemoryPushedRequestStore
import kots.oauth2.store.memory.InMemoryReplayStore
import kots.oauth2.store.memory.InMemoryTokenStore
import org.http4s.HttpRoutes
import org.http4s.ember.server.EmberServerBuilder

object Development {

  val AnyHost: com.comcast.ip4s.Ipv4Address =
    com.comcast.ip4s.Ipv4Address.fromBytes(0, 0, 0, 0)

  val SeedClientId: String = "dev-client"

  val SeedClientSecret: String = "dev-secret"

  val SeedSubject: String = "dev-user"

  val SeedKeyId: String = "dev-key"

  val SeedIssuer: String = "https://dev.example"

  def systemClock[F[_]: Async]: Clock[F] =
    new Clock[F] {
      def instant: F[java.time.Instant] = Async[F].delay(java.time.Instant.now())
    }

  def secureEntropy[F[_]: Async]: F[Entropy[F]] =
    Async[F].delay(new java.security.SecureRandom).map { random =>
      new Entropy[F] {
        def bytes(n: Int): F[Array[Byte]] =
          Async[F].delay {
            val out = new Array[Byte](n)
            random.nextBytes(out)
            out
          }
      }
    }

  def routes[F[_]: Async]: F[HttpRoutes[F]] = assembled[F].map { case (bound, _) => bound }

  def assembled[F[_]: Async]: F[(HttpRoutes[F], List[F[Int]])] = {
    val clock = systemClock[F]
    def unsafe[A](parsed: Either[ParseFailure, A]): A =
      parsed.fold(failure => sys.error(failure.toString), identity)
    val issuer = unsafe(Issuer.from(SeedIssuer))
    val clientId = unsafe(ClientId.from(SeedClientId))
    val subject = unsafe(Subject.from(SeedSubject))
    val scopes = unsafe(Scopes.parse("read write"))
    val seeded = Client(
      clientId,
      Set(unsafe(RedirectUri.from("https://client.example/cb"))),
      scopes,
      ClientAuthMethod.ClientSecretBasic,
      Some(ClientSecretHash.of(unsafe(ClientSecret.from(SeedClientSecret))))
    )
    val metadata = AuthorizationServerMetadata.of(
      issuer,
      unsafe(EndpointUri.from(s"$SeedIssuer/authorize")),
      unsafe(EndpointUri.from(s"$SeedIssuer/token")),
      Some(unsafe(EndpointUri.from(s"$SeedIssuer/revocation"))),
      Some(unsafe(EndpointUri.from(s"$SeedIssuer/introspection"))),
      Some(unsafe(EndpointUri.from(s"$SeedIssuer/jwks"))),
      scopes
    )
    val resource = ProtectedResourceMetadata(
      unsafe(ResourceIndicator.from("https://api.example")),
      List(issuer),
      scopes
    )
    for {
      entropy <- secureEntropy[F]
      pair <- Async[F].delay {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        generator.generateKeyPair
      }
      published = unsafe(publishedKey(pair))
      codes <- InMemoryCodeStore.create[F](clock)
      tokens <- InMemoryTokenStore.create[F](clock)
      grants <- InMemoryGrantStore.create[F]
      devices <- InMemoryDeviceStore.create[F](clock)
      pushed <- InMemoryPushedRequestStore.create[F](clock)
      replays <- InMemoryReplayStore.create[F](clock)
      keys <- InMemoryKeyStore.create[F]
      _ <- keys.add(published)
      clients <- InMemoryClientStore.create[F](List(seeded))
      consents <- InMemoryConsentStore.create[F]
      _ <- consents.grant(ConsentRecord(clientId, subject, scopes))
      login <- SessionLogin.create[F]
      _ <- login.login(subject)
      authentication = new RegisteredClientAuthentication[F](
        clients,
        Some(RegisteredClientAuthentication.Assertions(issuer, replays, clock))
      )
      signing = TokenService.Signing(issuer, SigningKey(published.kid, Alg.RS256, pair.getPrivate))
      service = new TokenService[F](
        codes,
        tokens,
        grants,
        devices,
        clock,
        entropy,
        LifetimePolicy.defaults,
        Some(signing)
      )
      registration = new RegistrationEndpoint[F](new RegistrationService[F](clients, entropy))
    } yield assembledOf(
      List(codes.sweep, tokens.sweep, devices.sweep, pushed.sweep, replays.sweep),
      Interpreter.routes[F](
        List(
          Server.authorize(
            new AuthorizationEndpoint[F](
              clients,
              login,
              new AuthorizationService[F](codes, consents, clock, entropy, LifetimePolicy.defaults),
              issuer,
              Some(pushed)
            )
          ),
          Server.par(
            new PushedAuthorizationEndpoint[F](
              authentication,
              new PushedAuthorizationService[F](pushed, clock, entropy, LifetimePolicy.defaults)
            )
          ),
          Server.register(registration),
          Server.registrationRead(registration),
          Server.registrationUpdate(registration),
          Server.registrationDelete(registration),
          Server.token(new TokenEndpoint[F](authentication, service)),
          Server.revocation(new RevocationEndpoint[F](authentication, tokens, grants)),
          Server.introspection(new IntrospectionEndpoint[F](authentication, tokens, grants)),
          Server.deviceAuthorization(
            new DeviceAuthorizationEndpoint[F](
              authentication,
              new DeviceAuthorizationService[F](
                devices,
                clock,
                entropy,
                LifetimePolicy.defaults,
                unsafe(EndpointUri.from(s"$SeedIssuer/device"))
              )
            )
          ),
          Server.metadata(metadata),
          Server.resourceMetadata(resource),
          Server.jwks(keys.jwks),
          Server.health[F],
          Server.ready(
            new kots.oauth2.server.Readiness[F](
              List(
                "clients" -> clients.find(clientId).map(_.isDefined),
                "keys" -> keys.jwks.map(_.keys.nonEmpty)
              )
            )
          )
        )
      )
    )
  }

  private def assembledOf[F[_]](
      sweeps: List[F[Int]],
      bound: HttpRoutes[F]
  ): (HttpRoutes[F], List[F[Int]]) =
    (bound, sweeps)

  val SweepInterval: scala.concurrent.duration.FiniteDuration =
    scala.concurrent.duration.DurationInt(60).seconds

  def server[F[_]: Async: fs2.io.net.Network](port: Port): Resource[F, org.http4s.server.Server] =
    Resource
      .eval(assembled[F])
      .flatMap { case (bound, sweeps) =>
        Resource.eval(InMemoryMetrics.create[F]).flatMap { metrics =>
          Resource.eval(secureEntropy[F]).flatMap { entropy =>
            EmberServerBuilder
              .default[F]
              .withHost(Development.AnyHost)
              .withPort(port)
              .withHttpApp(Correlated(entropy, Measured(metrics, bound)).orNotFound)
              .build
              .flatMap(server => Sweeper.stream[F](SweepInterval, sweeps).compile.drain.background.as(server))
          }
        }
      }

  private def publishedKey(pair: KeyPair): Either[ParseFailure, Jwk] = {
    val public = pair.getPublic.asInstanceOf[RSAPublicKey]
    def parameter(value: java.math.BigInteger): String =
      Base64.getUrlEncoder.withoutPadding.encodeToString(value.toByteArray.dropWhile(_ == 0))
    kots.oauth2.core.KeyId
      .from(SeedKeyId)
      .flatMap(kid =>
        Jwk.rsa(kid, Alg.RS256, parameter(public.getModulus), parameter(public.getPublicExponent))
      )
  }
}
