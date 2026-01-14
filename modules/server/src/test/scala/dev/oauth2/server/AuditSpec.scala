package dev.oauth2.server

import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.AuthorizationCode
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Clock
import dev.oauth2.core.CodeChallenge
import dev.oauth2.core.CodeChallengeMethod
import dev.oauth2.core.CodeVerifier
import dev.oauth2.core.Entropy
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TokenRequest
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.memory.InMemoryAuditLog
import dev.oauth2.store.memory.InMemoryClientStore
import dev.oauth2.store.memory.InMemoryCodeStore
import dev.oauth2.store.memory.InMemoryDeviceStore
import dev.oauth2.store.memory.InMemoryGrantStore
import dev.oauth2.store.memory.InMemoryTokenStore
import munit.CatsEffectSuite

class AuditSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private val verifier: CodeVerifier =
    unsafe(CodeVerifier.from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))

  private val challenge: CodeChallenge =
    unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

  private val registered: Client = Client(
    clientId,
    Set(callback),
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private val recorded: CodeRecord = CodeRecord(
    code = unsafe(AuthorizationCode.from("code-1")),
    clientId = clientId,
    redirectUri = callback,
    subject = subject,
    scopes = unsafe(Scopes.parse("read")),
    details = AuthorizationDetails.empty,
    pkce = Some(Pkce(challenge, CodeChallengeMethod.S256)),
    expiresAt = Start.plusSeconds(60L)
  )

  test("the log sees issuance, refresh, revocation, introspection and a refused authentication") {
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
    for {
      log <- InMemoryAuditLog.create[IO]
      codes <- InMemoryCodeStore.create[IO](clock)
      _ <- codes.save(recorded)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
      devices <- InMemoryDeviceStore.create[IO](clock)
      clients <- InMemoryClientStore.create[IO](List(registered))
      authentication = new RegisteredClientAuthentication[IO](clients, None, Some(log))
      service = new TokenService[IO](
        codes,
        tokens,
        grants,
        devices,
        clock,
        entropy,
        LifetimePolicy.defaults,
        None,
        Some(log)
      )
      revocation = new RevocationEndpoint[IO](authentication, tokens, grants, Some(log))
      introspection = new IntrospectionEndpoint[IO](authentication, tokens, grants, Some(log))
      issued <- service.authorizationCode(
        TokenRequest.Code(unsafe(AuthorizationCode.from("code-1")), None, verifier, clientId),
        registered
      )
      minted = issued.toOption.get
      refreshed <- service.refresh(TokenRequest.Refresh(minted.refreshToken.get, None, clientId), registered)
      rotated = refreshed.toOption.get
      basic = Some(
        java.util.Base64.getEncoder.encodeToString("client-1:s3cret".getBytes("UTF-8"))
      )
      _ <- revocation(
        basic,
        Map("token" -> rotated.refreshToken.get.value, "token_type_hint" -> "refresh_token")
      )
      _ <- introspection(basic, Map("token" -> rotated.accessToken.value))
      _ <- authentication.authenticate(
        unsafe(
          dev.oauth2.core.ClientAuthInput
            .from(
              Some(java.util.Base64.getEncoder.encodeToString("client-1:wrong".getBytes("UTF-8"))),
              Map.empty
            )
            .toEither
            .left
            .map(_ => ParseFailure("fixture", "fixture"))
        )
      )
      events <- log.events
    } yield {
      val names = events.map(_.name).toList
      assertEquals(names.take(2), List("issued", "refreshed"))
      assert(names.contains("revoked"))
      assert(names.contains("introspected"))
      assert(names.contains("authentication_failed"))
      assert(events.collectFirst { case e: dev.oauth2.store.AuditEvent.Introspected => e.active }.contains(false))
    }
  }
}
