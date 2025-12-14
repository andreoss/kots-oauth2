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
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TokenRequest
import dev.oauth2.core.DeviceCode
import dev.oauth2.core.UserCode
import dev.oauth2.store.Client
import dev.oauth2.store.CodeRecord
import dev.oauth2.store.DeviceRecord
import dev.oauth2.store.Grant
import dev.oauth2.store.memory.InMemoryCodeStore
import dev.oauth2.store.memory.InMemoryDeviceStore
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
      devices <- InMemoryDeviceStore.create[IO](clock)
    } yield (new TokenService[IO](codes, tokens, grants, devices, clock, entropy, policy), tokens, grants)
  }

  private def signedSetup: IO[(TokenService[IO], InMemoryTokenStore[IO])] = {
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
    val signing = TokenService.Signing(
      unsafe(dev.oauth2.core.Issuer.from("https://server.example")),
      dev.oauth2.jose.Fakes.signingKey
    )
    for {
      codes <- InMemoryCodeStore.create[IO](clock)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
      devices <- InMemoryDeviceStore.create[IO](clock)
    } yield (
      new TokenService[IO](
        codes,
        tokens,
        grants,
        devices,
        clock,
        entropy,
        LifetimePolicy.defaults,
        Some(signing)
      ),
      tokens
    )
  }

  test("a configured signer mints a verifiable jwt access token") {
    for {
      pair <- signedSetup
      (service, _) = pair
      issued <- service.clientCredentials(TokenRequest.ClientCredentials(None, clientId), client())
    } yield {
      val minted = issued.toOption.get
      val published = dev.oauth2.jose.Jwks(List(dev.oauth2.jose.Fakes.signingJwk))
      val parsed = dev.oauth2.jose.Jwt.claims(minted.accessToken.value, published, Start).toOption.get
      assertEquals(parsed.issuer.value, "https://server.example")
      assertEquals(parsed.subject.value, clientId.value)
      assertEquals(parsed.clientId, clientId)
      assertEquals(parsed.scopes, unsafe(Scopes.parse("read")))
      assertEquals(parsed.issuedAt, Start)
      assertEquals(parsed.expiresAt, Start.plusSeconds(3600L))
    }
  }

  test("a minted jwt access token is still found by its hash") {
    for {
      pair <- signedSetup
      (service, tokens) = pair
      issued <- service.clientCredentials(TokenRequest.ClientCredentials(None, clientId), client())
      found <- tokens.findByAccess(issued.toOption.get.accessToken)
    } yield assertEquals(found.map(_.clientId), Some(clientId))
  }

  private def deviceRecord(
      subject: Option[Subject] = None,
      denied: Boolean = false,
      client: ClientId = clientId,
      expiresAt: Instant = Start.plusSeconds(1800L),
      lastPolledAt: Option[Instant] = None
  ): DeviceRecord =
    DeviceRecord(
      deviceCode = unsafe(DeviceCode.from("device-1")),
      userCode = unsafe(UserCode.from("BCDF-GHJK")),
      clientId = client,
      scopes = unsafe(Scopes.parse("read")),
      expiresAt = expiresAt,
      subject = subject,
      denied = denied,
      lastPolledAt = lastPolledAt
    )

  private def deviceRequest: TokenRequest.Device =
    TokenRequest.Device(unsafe(DeviceCode.from("device-1")), clientId)

  private def deviceSetup(stored: DeviceRecord): IO[(TokenService[IO], InMemoryDeviceStore[IO], IO[Unit])] = {
    var now = Start
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO(now)
    }
    var calls: Int = 0
    val entropy = new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO {
        calls += 1
        Array.fill(n)(calls.toByte)
      }
    }
    val advance = IO { now = now.plusSeconds(DeviceAuthorizationService.Interval.seconds) }
    for {
      codes <- InMemoryCodeStore.create[IO](clock)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
      devices <- InMemoryDeviceStore.create[IO](clock)
      _ <- devices.save(stored)
    } yield (
      new TokenService[IO](codes, tokens, grants, devices, clock, entropy, LifetimePolicy.defaults),
      devices,
      advance
    )
  }

  private def client(
      id: ClientId = clientId,
      method: ClientAuthMethod = ClientAuthMethod.ClientSecretBasic
  ): Client =
    Client(
      id,
      Set(callback),
      unsafe(Scopes.parse("read")),
      method,
      if (method == ClientAuthMethod.None) None
      else Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
    )

  private val boundResource: dev.oauth2.core.ResourceIndicator =
    unsafe(dev.oauth2.core.ResourceIndicator.from("https://api.example"))

  test("a client credentials token is bound to the requested resource") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      issued <- service.clientCredentials(
        TokenRequest.ClientCredentials(None, clientId, Some(boundResource)),
        client()
      )
    } yield assertEquals(issued.toOption.get.record.audience.map(_.value), Some("https://api.example"))
  }

  test("a code exchange binds the token to the resource of its code") {
    for {
      triple <- setup(record("code-1").copy(resource = Some(boundResource)))
      (service, _, _) = triple
      issued <- service.authorizationCode(request("code-1", verifier), client())
    } yield assertEquals(issued.toOption.get.record.audience.map(_.value), Some("https://api.example"))
  }

  test("a refresh keeps the audience of the rotated token") {
    for {
      triple <- setup(record("code-1").copy(resource = Some(boundResource)))
      (service, _, _) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      rotated <- service.refresh(
        TokenRequest.Refresh(first.toOption.get.refreshToken.get, None, clientId),
        client()
      )
    } yield assertEquals(rotated.toOption.get.record.audience.map(_.value), Some("https://api.example"))
  }

  test("a device token is bound to the resource of its authorization") {
    for {
      triple <- deviceSetup(deviceRecord(subject = Some(subject)).copy(resource = Some(boundResource)))
      (service, _, _) = triple
      issued <- service.deviceCode(deviceRequest, client())
    } yield assertEquals(issued.toOption.get.record.audience.map(_.value), Some("https://api.example"))
  }

  private def issuedSubject(service: TokenService[IO]): IO[dev.oauth2.store.IssuedToken] =
    service
      .authorizationCode(request("code-1", verifier), client())
      .map(_.fold(error => sys.error(error.code), identity))

  private def exchangeOf(
      subjectToken: dev.oauth2.core.AccessToken,
      actorToken: Option[dev.oauth2.core.AccessToken] = None,
      audience: Option[String] = None,
      scope: Option[String] = None
  ): TokenRequest.Exchange =
    TokenRequest.Exchange(
      subjectToken,
      actorToken,
      audience.map(raw => unsafe(dev.oauth2.core.Audience.from(raw))),
      None,
      scope.map(raw => unsafe(Scopes.parse(raw))),
      clientId
    )

  test("an exchange answers a new audience bound token for a valid subject token") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      subject <- issuedSubject(service)
      result <- service.exchange(
        exchangeOf(subject.accessToken, audience = Some("https://api.example")),
        client()
      )
    } yield {
      val minted = result.toOption.get
      assertEquals(minted.record.subject, subject.record.subject)
      assertEquals(minted.record.scopes, subject.record.scopes)
      assertEquals(minted.record.audience.map(_.value), Some("https://api.example"))
      assertEquals(minted.record.actor, None)
      assertEquals(minted.refreshToken, None)
      assert(minted.accessToken != subject.accessToken)
    }
  }

  test("an exchange records the resource as the audience when no audience is named") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      subject <- issuedSubject(service)
      result <- service.exchange(
        exchangeOf(subject.accessToken)
          .copy(resource = Some(unsafe(dev.oauth2.core.ResourceIndicator.from("https://api.example/v1")))),
        client()
      )
    } yield assertEquals(result.toOption.get.record.audience.map(_.value), Some("https://api.example/v1"))
  }

  test("an exchange with an actor token records the acting subject") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      subject <- issuedSubject(service)
      acting <- service.clientCredentials(TokenRequest.ClientCredentials(None, clientId), client())
      result <- service.exchange(
        exchangeOf(subject.accessToken, actorToken = Some(acting.toOption.get.accessToken)),
        client()
      )
    } yield assertEquals(result.toOption.get.record.actor.map(_.value), Some(clientId.value))
  }

  test("an exchange narrows the scope and refuses a widening") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      subject <- issuedSubject(service)
      narrowed <- service.exchange(exchangeOf(subject.accessToken, scope = Some("read")), client())
      widened <- service.exchange(exchangeOf(subject.accessToken, scope = Some("read write")), client())
    } yield {
      assertEquals(narrowed.toOption.get.record.scopes, unsafe(Scopes.parse("read")))
      assertEquals(widened.left.toOption.map(_.code), Some("invalid_scope"))
    }
  }

  test("an exchange with an unknown subject token is refused") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      result <- service.exchange(exchangeOf(unsafe(dev.oauth2.core.AccessToken.from("absent"))), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("an exchange of another client's token is refused") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      subject <- issuedSubject(service)
      result <- service.exchange(exchangeOf(subject.accessToken), client(id = otherClientId))
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("an exchange of a token from a revoked grant is refused") {
    for {
      triple <- setup(record("code-1"))
      (service, _, grants) = triple
      subject <- issuedSubject(service)
      _ <- grants.revoke(subject.record.grantId)
      result <- service.exchange(exchangeOf(subject.accessToken), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("a device poll before the approval is answered as authorization pending") {
    for {
      triple <- deviceSetup(deviceRecord())
      (service, _, _) = triple
      result <- service.deviceCode(deviceRequest, client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("authorization_pending"))
  }

  test("a device poll inside the interval is answered as slow down") {
    for {
      triple <- deviceSetup(deviceRecord())
      (service, _, advance) = triple
      _ <- service.deviceCode(deviceRequest, client())
      early <- service.deviceCode(deviceRequest, client())
      _ <- advance
      paced <- service.deviceCode(deviceRequest, client())
    } yield {
      assertEquals(early.left.toOption.map(_.code), Some("slow_down"))
      assertEquals(paced.left.toOption.map(_.code), Some("authorization_pending"))
    }
  }

  test("an approved device code is exchanged exactly once") {
    for {
      triple <- deviceSetup(deviceRecord(subject = Some(subject)))
      (service, _, _) = triple
      issued <- service.deviceCode(deviceRequest, client())
      replayed <- service.deviceCode(deviceRequest, client())
    } yield {
      val minted = issued.toOption.get
      assertEquals(minted.record.subject, subject)
      assertEquals(minted.record.scopes, unsafe(Scopes.parse("read")))
      assert(minted.refreshToken.isDefined)
      assertEquals(replayed.left.toOption.map(_.code), Some("invalid_grant"))
    }
  }

  test("an approved device code for a public client is issued without a refresh token") {
    for {
      triple <- deviceSetup(deviceRecord(subject = Some(subject)))
      (service, _, _) = triple
      issued <- service.deviceCode(deviceRequest, client(method = ClientAuthMethod.None))
    } yield assertEquals(issued.toOption.get.refreshToken, None)
  }

  test("a denied device code is answered as access denied") {
    for {
      triple <- deviceSetup(deviceRecord(denied = true))
      (service, _, _) = triple
      result <- service.deviceCode(deviceRequest, client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("access_denied"))
  }

  test("an expired device code is answered as expired token") {
    for {
      triple <- deviceSetup(deviceRecord(expiresAt = Start))
      (service, _, _) = triple
      result <- service.deviceCode(deviceRequest, client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("expired_token"))
  }

  test("a device code of another client is refused as an invalid grant") {
    for {
      triple <- deviceSetup(deviceRecord(client = otherClientId))
      (service, _, _) = triple
      result <- service.deviceCode(deviceRequest, client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("an unknown device code is refused as an invalid grant") {
    for {
      triple <- deviceSetup(deviceRecord())
      (service, _, _) = triple
      result <- service.deviceCode(
        TokenRequest.Device(unsafe(DeviceCode.from("device-2")), clientId),
        client()
      )
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("exchange issues an access and a refresh token for a valid code") {
    for {
      triple <- setup(record("code-1"))
      (service, tokens, grants) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
      minted = result.toOption.get
      stored <- tokens.findByAccess(minted.accessToken)
      grant <- grants.find(minted.record.grantId)
    } yield {
      assert(result.isRight)
      assertEquals(minted.record.subject, subject)
      assertEquals(minted.record.scopes, unsafe(Scopes.parse("read")))
      assert(minted.refreshToken.isDefined)
      assert(stored.isDefined)
      assert(grant.isDefined)
    }
  }

  test("exchange stores only the hash of the issued tokens") {
    for {
      triple <- setup(record("code-1"))
      (service, tokens, _) = triple
      result <- service.authorizationCode(request("code-1", verifier), client())
      stored <- tokens.findByAccess(result.toOption.get.accessToken)
      byRefresh <- tokens.findByRefresh(result.toOption.get.refreshToken.get)
    } yield {
      assertNotEquals(stored.map(_.accessTokenHash.value), result.toOption.map(_.accessToken.value))
      assert(stored.exists(_.matchesAccess(result.toOption.get.accessToken)))
      assert(byRefresh.exists(_.matchesRefresh(result.toOption.get.refreshToken.get)))
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
      assertEquals(result.toOption.map(_.record.accessExpiresAt), Some(Start.plusSeconds(60L)))
      assertEquals(result.toOption.map(_.record.refreshExpiresAt), Some(Some(Start.plusSeconds(120L))))
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
      grant <- grants.find(result.toOption.get.record.grantId)
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
      grant <- grants.find(minted.record.grantId)
      stored <- tokens.findByAccess(minted.accessToken)
    } yield {
      assertEquals(grant.map(_.revoked), Some(true))
      assertEquals(stored, None)
    }
  }

  test("refresh rotates the access and the refresh token") {
    for {
      triple <- setup(record("code-1"))
      (service, tokens, _) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      issued = first.toOption.get
      second <- service.refresh(TokenRequest.Refresh(issued.refreshToken.get, None, clientId), client())
      rotated = second.toOption.get
      byOld <- tokens.findByRefresh(issued.refreshToken.get)
      byNew <- tokens.findByRefresh(rotated.refreshToken.get)
      oldAccess <- tokens.findByAccess(issued.accessToken)
    } yield {
      assert(second.isRight)
      assertNotEquals(rotated.accessToken.value, issued.accessToken.value)
      assertNotEquals(rotated.refreshToken.map(_.value), issued.refreshToken.map(_.value))
      assertEquals(byOld, None)
      assert(byNew.isDefined)
      assertEquals(oldAccess, None)
    }
  }

  test("refresh keeps the grant, the subject and the scope of the family") {
    for {
      triple <- setup(record("code-1"))
      (service, tokens, grants) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      issued = first.toOption.get
      second <- service.refresh(TokenRequest.Refresh(issued.refreshToken.get, None, clientId), client())
      rotated = second.toOption.get
      stored <- tokens.findByAccess(rotated.accessToken)
      grant <- grants.find(rotated.record.grantId)
    } yield {
      assertEquals(rotated.record.grantId, issued.record.grantId)
      assertEquals(rotated.record.subject, subject)
      assertEquals(rotated.record.scopes, unsafe(Scopes.parse("read")))
      assert(stored.isDefined)
      assertEquals(grant.map(_.revoked), Some(false))
    }
  }

  test("refresh keeps the refresh expiry of the family") {
    val policy = LifetimePolicy.defaults.copy(
      accessToken = unsafe(Lifetime.fromSeconds(60L)),
      refreshToken = unsafe(Lifetime.fromSeconds(120L))
    )
    for {
      triple <- setup(record("code-1"), policy)
      (service, _, _) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      issued = first.toOption.get
      second <- service.refresh(TokenRequest.Refresh(issued.refreshToken.get, None, clientId), client())
    } yield assertEquals(
      second.toOption.map(_.record.refreshExpiresAt),
      first.toOption.map(_.record.refreshExpiresAt)
    )
  }

  test("refresh narrows the scope and refuses a wider one") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      issued = first.toOption.get
      narrower <- service.refresh(
        TokenRequest.Refresh(issued.refreshToken.get, Some(unsafe(Scopes.parse("read"))), clientId),
        client()
      )
      wider <- service.refresh(
        TokenRequest.Refresh(
          narrower.toOption.get.refreshToken.get,
          Some(unsafe(Scopes.parse("read write"))),
          clientId
        ),
        client()
      )
    } yield {
      assertEquals(narrower.toOption.map(_.record.scopes), Some(unsafe(Scopes.parse("read"))))
      assertEquals(wider.left.toOption.map(_.code), Some("invalid_scope"))
    }
  }

  test("client credentials issue an access token without a refresh token") {
    for {
      triple <- setup(record("code-1"))
      (service, tokens, _) = triple
      result <- service.clientCredentials(TokenRequest.ClientCredentials(None, clientId), client())
      minted = result.toOption.get
      stored <- tokens.findByAccess(minted.accessToken)
    } yield {
      assertEquals(minted.refreshToken, None)
      assertEquals(minted.record.subject.value, clientId.value)
      assertEquals(minted.record.scopes, unsafe(Scopes.parse("read")))
      assert(stored.isDefined)
    }
  }

  test("client credentials refuse a scope the client is not registered for") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      result <- service.clientCredentials(
        TokenRequest.ClientCredentials(Some(unsafe(Scopes.parse("read write"))), clientId),
        client()
      )
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_scope"))
  }

  test("client credentials are refused for a public client") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      result <- service.clientCredentials(
        TokenRequest.ClientCredentials(None, clientId),
        client(method = ClientAuthMethod.None)
      )
    } yield assertEquals(result.left.toOption.map(_.code), Some("unauthorized_client"))
  }

  test("refresh refuses an unknown refresh token") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      unknown <- service.refresh(
        TokenRequest.Refresh(unsafe(RefreshToken.from("rt-absent")), None, clientId),
        client()
      )
    } yield assertEquals(unknown.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("refresh refuses a token issued to another client") {
    for {
      triple <- setup(record("code-1"))
      (service, _, _) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      issued = first.toOption.get
      result <- service.refresh(
        TokenRequest.Refresh(issued.refreshToken.get, None, otherClientId),
        client(otherClientId)
      )
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("refresh revokes the family when a retired refresh token is reused") {
    for {
      triple <- setup(record("code-1"))
      (service, tokens, grants) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      issued = first.toOption.get
      second <- service.refresh(TokenRequest.Refresh(issued.refreshToken.get, None, clientId), client())
      rotated = second.toOption.get
      replay <- service.refresh(TokenRequest.Refresh(issued.refreshToken.get, None, clientId), client())
      grant <- grants.find(rotated.record.grantId)
      access <- tokens.findByAccess(rotated.accessToken)
      refresh <- tokens.findByRefresh(rotated.refreshToken.get)
    } yield {
      assertEquals(replay.left.toOption.map(_.code), Some("invalid_grant"))
      assertEquals(grant.map(_.revoked), Some(true))
      assertEquals(access, None)
      assertEquals(refresh, None)
    }
  }

  test("refresh refuses a revoked grant") {
    for {
      triple <- setup(record("code-1"))
      (service, _, grants) = triple
      first <- service.authorizationCode(request("code-1", verifier), client())
      issued = first.toOption.get
      _ <- grants.revoke(issued.record.grantId)
      result <- service.refresh(TokenRequest.Refresh(issued.refreshToken.get, None, clientId), client())
    } yield assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
  }

  test("an unknown code revokes nothing") {
    val kept = unsafe(GrantId.from("grant-1"))
    for {
      triple <- setup(record("code-1"))
      (service, _, grants) = triple
      _ <- grants.save(
        Grant(kept, clientId, subject, Scopes.empty, AuthorizationDetails.empty, revoked = false)
      )
      result <- service.authorizationCode(request("code-2", verifier), client())
      grant <- grants.find(kept)
    } yield {
      assertEquals(result.left.toOption.map(_.code), Some("invalid_grant"))
      assertEquals(grant.map(_.revoked), Some(false))
    }
  }
}
