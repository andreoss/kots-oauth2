package dev.oauth2.server

import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.AuthorizationDetails
import dev.oauth2.core.AuthorizationRequest
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.Clock
import dev.oauth2.core.CodeChallenge
import dev.oauth2.core.CodeChallengeMethod
import dev.oauth2.core.CodeVerifier
import dev.oauth2.core.Entropy
import dev.oauth2.core.Lifetime
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.ResponseType
import dev.oauth2.core.Scope
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.store.Client
import dev.oauth2.store.memory.InMemoryCodeStore
import munit.CatsEffectSuite

class AuthorizationServiceSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private val other: RedirectUri = unsafe(RedirectUri.from("https://client.example/other"))

  private val verifier: CodeVerifier =
    unsafe(CodeVerifier.from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))

  private val challenge: CodeChallenge =
    unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

  private val pkce: Pkce = Pkce(challenge, CodeChallengeMethod.S256)

  private def request(
      redirectUri: Option[RedirectUri],
      scope: Option[String],
      challenge: Option[Pkce]
  ): AuthorizationRequest =
    AuthorizationRequest(
      responseType = ResponseType.Code,
      clientId = clientId,
      redirectUri = redirectUri,
      scope = scope.map(raw => unsafe(Scopes.parse(raw))).getOrElse(Scopes.empty),
      state = None,
      pkce = challenge
    )

  private final class Ticking(var now: Instant) extends Clock[IO] {
    def instant: IO[Instant] = IO.pure(now)
  }

  private def serviceOf(
      clock: Clock[IO] = new Ticking(Start),
      policy: LifetimePolicy = LifetimePolicy.defaults
  ): IO[(AuthorizationService[IO], InMemoryCodeStore[IO], Clock[IO])] = {
    val entropy = new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO.pure(Array.fill(n)(7.toByte))
    }
    InMemoryCodeStore.create[IO](clock).map { codes =>
      (new AuthorizationService[IO](codes, clock, entropy, policy), codes, clock)
    }
  }

  private def client(
      uris: Set[RedirectUri],
      scopes: String,
      method: ClientAuthMethod = ClientAuthMethod.ClientSecretBasic
  ): Client =
    Client(
      clientId,
      uris,
      unsafe(Scopes.parse(scopes)),
      method,
      if (method == ClientAuthMethod.None) None else Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
    )

  test("issuance stores a code bound to the client, redirect, subject and challenge") {
    val registered = client(Set(callback), "read write")
    for {
      triple <- serviceOf()
      (service, codes, _) = triple
      issued <- service.issue(request(Some(callback), Some("read"), Some(pkce)), registered, subject, AuthorizationDetails.empty)
      record <- issued.fold(_ => IO.pure(None), codes.consume)
    } yield {
      assert(issued.isRight)
      assertEquals(record.map(_.clientId), Some(clientId))
      assertEquals(record.map(_.redirectUri), Some(callback))
      assertEquals(record.map(_.subject), Some(subject))
      assertEquals(record.map(_.scopes), Some(unsafe(Scopes.parse("read"))))
      assertEquals(record.map(_.pkce), Some(Some(pkce)))
    }
  }

  test("issuance mints a code of the configured entropy length") {
    val registered = client(Set(callback), "read")
    for {
      triple <- serviceOf()
      (service, _, _) = triple
      issued <- service.issue(request(Some(callback), Some("read"), Some(pkce)), registered, subject, AuthorizationDetails.empty)
    } yield assertEquals(issued.toOption.map(_.value.length), Some(AuthorizationService.CodeEntropyBytes * 2))
  }

  test("issuance expires the code by the policy") {
    val policy = LifetimePolicy.defaults.copy(authorizationCode = unsafe(Lifetime.fromSeconds(30L)))
    val registered = client(Set(callback), "read")
    val ticking = new Ticking(Start)
    for {
      triple <- serviceOf(ticking, policy)
      (service, codes, _) = triple
      issued <- service.issue(request(Some(callback), Some("read"), Some(pkce)), registered, subject, AuthorizationDetails.empty)
      live <- issued.fold(_ => IO.pure(None), codes.consume)
      again <- service.issue(request(Some(callback), Some("read"), Some(pkce)), registered, subject, AuthorizationDetails.empty)
      expired <- {
        ticking.now = Start.plusSeconds(31L)
        again.fold(_ => IO.pure(None), codes.consume)
      }
    } yield {
      assert(live.isDefined)
      assertEquals(expired, None)
    }
  }

  test("issuance refuses a redirect uri that is not registered") {
    val registered = client(Set(callback), "read")
    for {
      triple <- serviceOf()
      (service, _, _) = triple
      issued <- service.issue(request(Some(other), Some("read"), Some(pkce)), registered, subject, AuthorizationDetails.empty)
    } yield assertEquals(issued.left.toOption.map(_.code), Some("invalid_request"))
  }

  test("issuance requires redirect_uri when several are registered") {
    val registered = client(Set(callback, other), "read")
    for {
      triple <- serviceOf()
      (service, _, _) = triple
      issued <- service.issue(request(None, Some("read"), Some(pkce)), registered, subject, AuthorizationDetails.empty)
    } yield assertEquals(issued.left.toOption.map(_.code), Some("invalid_request"))
  }

  test("issuance takes the single registered redirect uri when none is given") {
    val registered = client(Set(callback), "read")
    for {
      triple <- serviceOf()
      (service, codes, _) = triple
      issued <- service.issue(request(None, Some("read"), Some(pkce)), registered, subject, AuthorizationDetails.empty)
      record <- issued.fold(_ => IO.pure(None), codes.consume)
    } yield assertEquals(record.map(_.redirectUri), Some(callback))
  }

  test("issuance refuses a scope the client does not have") {
    val registered = client(Set(callback), "read")
    val wanted = Scopes.of(List(unsafe(Scope.from("write"))))
    for {
      triple <- serviceOf()
      (service, _, _) = triple
      issued <- service.issue(
        request(Some(callback), None, Some(pkce)).copy(scope = wanted),
        registered,
        subject,
        AuthorizationDetails.empty
      )
    } yield assertEquals(issued.left.toOption.map(_.code), Some("invalid_scope"))
  }

  test("issuance refuses a request without a code challenge") {
    val registered = client(Set(callback), "read")
    for {
      triple <- serviceOf()
      (service, _, _) = triple
      issued <- service.issue(request(Some(callback), Some("read"), None), registered, subject, AuthorizationDetails.empty)
    } yield assertEquals(issued.left.toOption.map(_.code), Some("invalid_request"))
  }

  test("issuance refuses the plain code challenge method") {
    val registered = client(Set(callback), "read")
    val plain = Pkce(unsafe(CodeChallenge.from(verifier.value)), CodeChallengeMethod.Plain)
    for {
      triple <- serviceOf()
      (service, _, _) = triple
      issued <- service.issue(request(Some(callback), Some("read"), Some(plain)), registered, subject, AuthorizationDetails.empty)
    } yield assertEquals(issued.left.toOption.map(_.code), Some("invalid_request"))
  }

  test("issuance refuses a public client without a code challenge") {
    val registered = client(Set(callback), "read", ClientAuthMethod.None)
    for {
      triple <- serviceOf()
      (service, _, _) = triple
      issued <- service.issue(request(Some(callback), Some("read"), None), registered, subject, AuthorizationDetails.empty)
    } yield assertEquals(issued.left.toOption.map(_.code), Some("invalid_request"))
  }
}
