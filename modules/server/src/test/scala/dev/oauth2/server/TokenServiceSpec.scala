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
import dev.oauth2.core.GrantId
import dev.oauth2.core.Lifetime
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TokenRequest
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.Grant
import dev.oauth2.store.memory.InMemoryCodeStore
import dev.oauth2.store.memory.InMemoryGrantStore
import dev.oauth2.store.memory.InMemoryTokenStore
import munit.CatsEffectSuite

class TokenServiceSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val otherClientId: ClientId = unsafe(ClientId.from("client-2"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private val otherCallback: RedirectUri = unsafe(RedirectUri.from("https://client.example/other"))

  private val verifier: CodeVerifier =
    unsafe(CodeVerifier.from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))

  private val wrongVerifier: CodeVerifier =
    unsafe(CodeVerifier.from("~vjfKQEFmDCOvyYAoUcxYCLkKmQTWyaWvGXFKcUwUfHk"))

  private val challenge: CodeChallenge =
    unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

  private val pkce: Pkce = Pkce(challenge, CodeChallengeMethod.S256)

  private val plain: Pkce =
    Pkce(unsafe(CodeChallenge.from(verifier.value)), CodeChallengeMethod.Plain)

  private def record(
      name: String,
      client: ClientId = clientId,
      redirect: RedirectUri = callback,
      challenge: Option[Pkce] = Some(pkce),
      expiresAt: Instant = Start.plusSeconds(60L)
  ): CodeRecord =
    CodeRecord(
      code = unsafe(AuthorizationCode.from(name)),
      clientId = client,
      redirectUri = redirect,
      subject = subject,
      scopes = unsafe(Scopes.parse("read")),
      details = AuthorizationDetails.empty,
      pkce = challenge,
      expiresAt = expiresAt
    )

  private def request(
      code: String,
      verifier: CodeVerifier,
      redirect: Option[RedirectUri] = None
  ): TokenRequest.Code =
    TokenRequest.Code(unsafe(AuthorizationCode.from(code)), redirect, verifier, clientId)

  private def setup(
      stored: CodeRecord,
      policy: LifetimePolicy = LifetimePolicy.defaults
  ): IO[(TokenService[IO], InMemoryTokenStore[IO], InMemoryGrantStore[IO])] = {
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
      codes <- InMemoryCodeStore.create[IO](clock)
      _ <- codes.save(stored)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
    } yield (new TokenService[IO](codes, tokens, grants, clock, entropy, policy), tokens, grants)
  }

  private def client(id: ClientId = clientId, method: ClientAuthMethod = ClientAuthMethod.ClientSecretBasic): Client =
    Client(
      id,
      Set(callback),
      unsafe(Scopes.parse("read")),
      method,
      if (method == ClientAuthMethod.None) None else Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
    )

  test("exchange issues an access and a refresh token for a valid code") {
    for {
      triple <- setup(record("code-1"))
      (service, tokens, grants) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
      minted = result.toOption.get
      stored <- tokens.findByAccess(minted.accessToken)
      grant <- grants.find(minted.grantId)
    } yield {
      assert(result.isRight)
      assertEquals(minted.subject, subject)
      assertEquals(minted.scopes, unsafe(Scopes.parse("read")))
      assert(minted.refreshToken.isDefined)
      assert(stored.isDefined)
      assert(grant.isDefined)
    }
  }

  test("exchange applies the lifetime policy to the tokens") {
    val policy = LifetimePolicy.defaults.copy(
      accessToken = unsafe(Lifetime.fromSeconds(60L)),
      refreshToken = unsafe(Lifetime.fromSeconds(120L))
    )
    for {
      triple <- setup(record("code-1"), policy)
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
    } yield {
      assertEquals(result.toOption.map(_.accessExpiresAt), Some(Start.plusSeconds(60L)))
      assertEquals(result.toOption.map(_.refreshExpiresAt), Some(Some(Start.plusSeconds(120L))))
    }
  }

  test("exchange refuses an unknown code") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-2", verifier), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("exchange refuses a replayed code") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      second <- service.authorizationCode(request("code-1", verifier), client())
    } yield {
      assert(first.isRight)
      assertEquals(second.left.toOption.map(_.code), Some("invalid_grant"))
    }
  }

  test("exchange refuses a code issued to another client") {
    val stored = record("code-1", client = otherClientId)
    for {
      triple <- setup(stored)
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("exchange refuses a mismatched redirect uri") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", verifier, Some(otherCallback)), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("exchange accepts the redirect uri of the code") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", verifier, Some(callback)), client())
    } yield assert(result.isRight)
  }

  test("exchange refuses a wrong code verifier") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", wrongVerifier), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("exchange refuses a code without a challenge") {
    for {
      triple <- setup(record("code-1", challenge = None))
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("exchange refuses the plain code challenge method") {
    for {
      triple <- setup(record("code-1", challenge = Some(plain)))
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("exchange refuses an expired code") {
    val stored = record("code-1", expiresAt = Start.minusSeconds(1L))
    for {
      triple <- setup(stored)
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("exchange gives no refresh token to a public client") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      result <- service.authorizationCode(request("code-1", verifier), client(method = ClientAuthMethod.None))
    } yield {
      assert(result.isRight)
      assertEquals(result.toOption.map(_.refreshToken), Some(None))
    }
  }

  test("exchange stores the grant as not revoked") {
    for {
      triple <- setup(record("code-1"))
      (service, _, grants) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
      grant <- grants.find(result.toOption.get.grantId)
    } yield assertEquals(grant.map(_.revoked), Some(false))
  }

  test("exchange refuses a replayed code") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      second <- service.authorizationCode(request("code-1", verifier), client())
    } yield {
      assert(first.isRight)
      assertEquals(second.left.toOption.map(_.code), Some("invalid_grant"))
    }
  }

  test("a replayed code revokes the grant it issued") {
    for {
      triple <- setup(record("code-1"))
      (service, tokens, grants) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      minted = first.toOption.get
      _ <- service.authorizationCode(request("code-1", verifier), client())
      grant <- grants.find(minted.grantId)
      stored <- tokens.findByAccess(minted.accessToken)
    } yield {
      assertEquals(grant.map(_.revoked), Some(true))
      assertEquals(stored, None)
    }
  }

  test("an unknown code revokes nothing") {
    val kept = unsafe(GrantId.from("grant-1"))
    for {
      triple <- setup(record("code-1"))
      (service, _, grants) = triple
      _ <- grants.save(Grant(kept, clientId, subject, Scopes.empty, AuthorizationDetails.empty, revoked = false))
      result <- service.authorizationCode(request("code-2", verifier), client())
      grant <- grants.find(kept)
    } yield {
      assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
      assertEquals(grant.map(_.revoked), Some(false))
    }
  }
}
