package kots.oauth2.host

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

import cats.effect.IO
import cats.effect.Ref
import kots.oauth2.client.BearerGuard
import kots.oauth2.core.Audience
import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientAssertion
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.Clock
import kots.oauth2.core.CodeChallenge
import kots.oauth2.core.CodeChallengeMethod
import kots.oauth2.core.CodeVerifier
import kots.oauth2.core.Entropy
import kots.oauth2.core.Issuer
import kots.oauth2.core.JwtId
import kots.oauth2.core.LifetimePolicy
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Pkce
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.http.Form
import kots.oauth2.http.Server
import kots.oauth2.jose.Alg
import kots.oauth2.jose.Dpop
import kots.oauth2.jose.Fakes
import kots.oauth2.jose.Jwks
import kots.oauth2.jose.Jws
import kots.oauth2.server.AuthorizationEndpoint
import kots.oauth2.server.AuthorizationService
import kots.oauth2.server.DpopProofs
import kots.oauth2.server.IntrospectionEndpoint
import kots.oauth2.server.RegisteredClientAuthentication
import kots.oauth2.server.SessionLogin
import kots.oauth2.server.TokenEndpoint
import kots.oauth2.server.TokenService
import kots.oauth2.store.Client
import kots.oauth2.store.CodeRecord
import kots.oauth2.store.ConsentRecord
import kots.oauth2.store.memory.InMemoryClientStore
import kots.oauth2.store.memory.InMemoryCodeStore
import kots.oauth2.store.memory.InMemoryConsentStore
import kots.oauth2.store.memory.InMemoryDeviceStore
import kots.oauth2.store.memory.InMemoryGrantStore
import kots.oauth2.store.memory.InMemoryReplayStore
import kots.oauth2.store.memory.InMemoryTokenStore
import fs2.Stream
import io.circe.Json
import munit.CatsEffectSuite
import org.http4s.BasicCredentials
import org.http4s.Header
import org.http4s.Headers
import org.http4s.HttpRoutes
import org.http4s.MediaType
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.Uri
import org.http4s.headers.Authorization
import org.http4s.headers.`Content-Type`
import org.typelevel.ci.CIString

class NegativeSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val TokenUri: String = "http://localhost/token"

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val issuer: Issuer = unsafe(Issuer.from("https://server.example"))

  private val verifier: CodeVerifier =
    unsafe(CodeVerifier.from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))

  private val challenge: CodeChallenge =
    unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

  private val recorded: CodeRecord = CodeRecord(
    code = unsafe(AuthorizationCode.from("code-1")),
    clientId = clientId,
    redirectUri = unsafe(RedirectUri.from("https://client.example/cb")),
    subject = unsafe(Subject.from("user-1")),
    scopes = unsafe(Scopes.parse("read")),
    details = AuthorizationDetails.empty,
    pkce = Some(Pkce(challenge, CodeChallengeMethod.S256)),
    expiresAt = Start.plusSeconds(60L)
  )

  private val registered: Client = Client(
    clientId,
    Set(unsafe(RedirectUri.from("https://client.example/cb"))),
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private val exchange: Map[String, String] = Map(
    "grant_type" -> "authorization_code",
    "code" -> "code-1",
    "code_verifier" -> verifier.value,
    "client_id" -> clientId.value
  )

  private val credentials: Map[String, String] =
    Map("grant_type" -> "client_credentials", "client_id" -> clientId.value)

  private val mtlsId: ClientId = unsafe(ClientId.from("client-mtls"))

  private val mtlsClient: Client = Client(
    mtlsId,
    Set.empty,
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.SelfSignedTlsClientAuth,
    None,
    certificateThumbprint = Some(
      unsafe(kots.oauth2.core.CertificateThumbprint.from(Fakes.ClientCertificateThumbprint))
    )
  )

  private val jwtId: ClientId = unsafe(ClientId.from("client-jwt"))

  private val jwtClient: Client = Client(
    jwtId,
    Set.empty,
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.PrivateKeyJwt,
    None,
    keys = Jwks(List(Fakes.signingJwk))
  )

  private def application: IO[
    (HttpRoutes[IO], Ref[IO, Instant], SessionLogin[IO], InMemoryConsentStore[IO])
  ] =
    for {
      moment <- Ref.of[IO, Instant](Start)
      clock = new Clock[IO] { def instant: IO[Instant] = moment.get }
      counter <- Ref.of[IO, Int](0)
      entropy = new Entropy[IO] {
        def bytes(n: Int): IO[Array[Byte]] =
          counter.updateAndGet(_ + 1).map(calls => Array.fill(n)(calls.toByte))
      }
      codes <- InMemoryCodeStore.create[IO](clock)
      _ <- codes.save(recorded)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
      devices <- InMemoryDeviceStore.create[IO](clock)
      replays <- InMemoryReplayStore.create[IO](clock)
      clients <- InMemoryClientStore.create[IO](List(registered, mtlsClient, jwtClient))
      consents <- InMemoryConsentStore.create[IO]
      login <- SessionLogin.create[IO]
      authentication = new RegisteredClientAuthentication[IO](
        clients,
        Some(RegisteredClientAuthentication.Assertions(issuer, replays, clock))
      )
      service = new TokenService[IO](
        codes,
        tokens,
        grants,
        devices,
        clock,
        entropy,
        LifetimePolicy.defaults,
        Some(TokenService.Signing(issuer, Fakes.signingKey))
      )
      proofs = TokenEndpoint.Proofs(new DpopProofs[IO](replays, clock), TokenUri)
      authorization = new AuthorizationEndpoint[IO](
        clients,
        login,
        new AuthorizationService[IO](codes, consents, clock, entropy, LifetimePolicy.defaults),
        issuer
      )
    } yield (
      Interpreter.routes[IO](
        List(
          Server.authorize(authorization),
          Server.token(new TokenEndpoint[IO](authentication, service, Some(proofs))),
          Server.introspection(new IntrospectionEndpoint[IO](authentication, tokens, grants))
        )
      ),
      moment,
      login,
      consents
    )

  private def post(form: Map[String, String], proof: Option[String] = None): Request[IO] =
    Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString(TokenUri),
      headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
        Headers(Authorization(BasicCredentials(clientId.value, "s3cret"))) ++
        Headers(proof.toList.map(value => Header.Raw(CIString("DPoP"), value))),
      body = Stream.emits(Form.render(form).getBytes(StandardCharsets.UTF_8).toSeq).covary[IO]
    )

  private def postWith(form: Map[String, String], secret: String): Request[IO] =
    Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString(TokenUri),
      headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
        Headers(Authorization(BasicCredentials(clientId.value, secret))),
      body = Stream.emits(Form.render(form).getBytes(StandardCharsets.UTF_8).toSeq).covary[IO]
    )

  private def introspect(token: String): Request[IO] =
    Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString("http://localhost/introspection"),
      headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
        Headers(Authorization(BasicCredentials(clientId.value, "s3cret"))),
      body = Stream
        .emits(Form.render(Map("token" -> token)).getBytes(StandardCharsets.UTF_8).toSeq)
        .covary[IO]
    )

  private def authorize(query: Map[String, String]): Request[IO] =
    Request[IO](
      method = Method.GET,
      uri = Uri.unsafeFromString("http://localhost/authorize?" + Form.render(query))
    )

  private val requested: Map[String, String] = Map(
    "response_type" -> "code",
    "client_id" -> clientId.value,
    "redirect_uri" -> "https://client.example/cb",
    "scope" -> "read",
    "state" -> "xyz",
    "code_challenge" -> challenge.value,
    "code_challenge_method" -> "S256"
  )

  private def body(response: Response[IO]): IO[String] =
    response.body.compile.toVector.map(bytes => new String(bytes.toArray, StandardCharsets.UTF_8))

  private def member(text: String, name: String): Option[io.circe.Json] =
    io.circe.parser.parse(text).toOption.flatMap(_.hcursor.downField(name).focus)

  private def field(text: String, name: String): String =
    io.circe.parser
      .parse(text)
      .toOption
      .flatMap(_.hcursor.get[String](name).toOption)
      .getOrElse(sys.error(s"no $name in $text"))

  private def location(response: Response[IO]): Option[String] =
    response.headers.headers.find(_.name.toString == "Location").map(_.value)

  private def query(response: Response[IO]): Map[String, String] =
    location(response)
      .flatMap(value => Form.parse(value.dropWhile(_ != '?').drop(1)).toOption)
      .getOrElse(sys.error("no redirect"))

  private def encoded(json: Json): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(json.noSpaces.getBytes(StandardCharsets.UTF_8))

  private def forged(alg: String): String = {
    val header = Json.obj(
      "typ" -> Json.fromString("dpop+jwt"),
      "alg" -> Json.fromString(alg),
      "jwk" -> Json.obj(
        "kty" -> Json.fromString("RSA"),
        "n" -> Json.fromString(Fakes.Modulus),
        "e" -> Json.fromString(Fakes.Exponent)
      )
    )
    val payload = Json.obj(
      "jti" -> Json.fromString("forged-1"),
      "htm" -> Json.fromString("POST"),
      "htu" -> Json.fromString(TokenUri),
      "iat" -> Json.fromLong(Start.getEpochSecond)
    )
    encoded(header) + "." + encoded(payload) + "." + "AA"
  }

  private def proven(jti: String): String =
    unsafe(
      Dpop.prove(
        Alg.RS256,
        Fakes.signingPair.getPrivate,
        Fakes.signingJwk,
        unsafe(JwtId.from(jti)),
        "POST",
        TokenUri,
        Start
      )
    )

  test("a replayed code revokes the tokens it already issued") {
    for {
      tuple <- application
      (served, _, _, _) = tuple
      first <- served.run(post(exchange)).value
      access <- body(first.get).map(field(_, "access_token"))
      before <- served.run(introspect(access)).value
      beforeText <- body(before.get)
      replayed <- served.run(post(exchange)).value
      replayedText <- body(replayed.get)
      after <- served.run(introspect(access)).value
      afterText <- body(after.get)
    } yield {
      assertEquals(first.get.status, Status.Ok)
      assertEquals(member(beforeText, "active"), Some(io.circe.Json.True))
      assertEquals(replayed.get.status, Status.BadRequest)
      assertEquals(field(replayedText, "error"), "invalid_grant")
      assertEquals(member(afterText, "active"), Some(io.circe.Json.False))
    }
  }

  test("an unregistered redirect uri is refused without a redirect") {
    for {
      tuple <- application
      (served, _, _, _) = tuple
      answered <- served
        .run(authorize(requested.updated("redirect_uri", "https://evil.example/cb")))
        .value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.BadRequest)
      assertEquals(location(response), None)
      assertEquals(field(text, "error"), "invalid_request")
      assert(!text.contains("evil.example"))
    }
  }

  test("a downgrade to the plain challenge method is refused without a code") {
    val user = unsafe(Subject.from("user-1"))
    for {
      tuple <- application
      (served, _, login, consents) = tuple
      _ <- consents.grant(ConsentRecord(clientId, user, unsafe(Scopes.parse("read"))))
      _ <- login.login(user)
      answered <- served
        .run(authorize(requested.updated("code_challenge_method", "plain")))
        .value
      response = answered.get
    } yield {
      assertEquals(response.status, Status.Found)
      assertEquals(query(response).get("error"), Some("invalid_request"))
      assertEquals(query(response).get("code"), None)
    }
  }

  test("a token request without the proven verifier is refused") {
    for {
      tuple <- application
      (served, _, _, _) = tuple
      answered <- served.run(post(exchange - "code_verifier")).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.BadRequest)
      assertEquals(field(text, "error"), "invalid_request")
    }
  }

  test("a proof by an unsigned or symmetric algorithm is refused") {
    for {
      tuple <- application
      (served, _, _, _) = tuple
      unsigned <- served.run(post(credentials, Some(forged("none")))).value
      unsignedText <- body(unsigned.get)
      symmetric <- served.run(post(credentials, Some(forged("HS256")))).value
      symmetricText <- body(symmetric.get)
    } yield {
      assertEquals(unsigned.get.status, Status.BadRequest)
      assertEquals(field(unsignedText, "error"), "invalid_dpop_proof")
      assertEquals(symmetric.get.status, Status.BadRequest)
      assertEquals(field(symmetricText, "error"), "invalid_dpop_proof")
    }
  }

  test("a replayed proof is refused") {
    val proof = proven("proof-1")
    for {
      tuple <- application
      (served, _, _, _) = tuple
      first <- served.run(post(credentials, Some(proof))).value
      firstText <- body(first.get)
      second <- served.run(post(credentials, Some(proof))).value
      secondText <- body(second.get)
    } yield {
      assertEquals(first.get.status, Status.Ok)
      assertEquals(field(firstText, "token_type"), "DPoP")
      assertEquals(second.get.status, Status.BadRequest)
      assertEquals(field(secondText, "error"), "invalid_dpop_proof")
    }
  }

  test("an expired code is refused") {
    for {
      tuple <- application
      (served, moment, _, _) = tuple
      _ <- moment.set(Start.plusSeconds(61L))
      answered <- served.run(post(exchange)).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.BadRequest)
      assertEquals(field(text, "error"), "invalid_grant")
    }
  }

  test("an expired access token is introspected as inactive") {
    for {
      tuple <- application
      (served, moment, _, _) = tuple
      issued <- served.run(post(exchange)).value
      access <- body(issued.get).map(field(_, "access_token"))
      _ <- moment.set(Start.plusSeconds(3601L))
      answered <- served.run(introspect(access)).value
      text <- body(answered.get)
    } yield {
      assertEquals(issued.get.status, Status.Ok)
      assertEquals(member(text, "active"), Some(io.circe.Json.False))
    }
  }

  test("a binding is granted only to the client that proved its certificate") {
    val mtlsRequest = Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString(TokenUri),
      headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
        Headers(
          Header.Raw(
            CIString("X-Client-Cert"),
            java.net.URLEncoder.encode(Fakes.ClientCertificatePem, "UTF-8")
          )
        ),
      body = Stream
        .emits(
          Form
            .render(Map("grant_type" -> "client_credentials", "client_id" -> mtlsId.value))
            .getBytes(StandardCharsets.UTF_8)
            .toSeq
        )
        .covary[IO]
    )
    def claimsOf(token: String) =
      kots.oauth2.jose.Jwt
        .claims(token, Jwks(List(Fakes.signingJwk)), Start)
        .toOption
        .get
    for {
      tuple <- application
      (served, _, _, _) = tuple
      bound <- served.run(mtlsRequest).value
      boundToken <- body(bound.get).map(field(_, "access_token"))
      plain <- served.run(post(credentials)).value
      plainToken <- body(plain.get).map(field(_, "access_token"))
    } yield {
      assertEquals(bound.get.status, Status.Ok)
      assertEquals(
        claimsOf(boundToken).x5t.map(_.value),
        Some(Fakes.ClientCertificateThumbprint)
      )
      assertEquals(claimsOf(plainToken).x5t, None)
    }
  }

  test("an authorization request without a code challenge is refused") {
    val user = unsafe(Subject.from("user-1"))
    for {
      tuple <- application
      (served, _, login, consents) = tuple
      _ <- consents.grant(ConsentRecord(clientId, user, unsafe(Scopes.parse("read"))))
      _ <- login.login(user)
      answered <- served.run(authorize(requested - "code_challenge")).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.BadRequest)
      assertEquals(field(text, "error"), "invalid_request")
      assertEquals(location(response), None)
    }
  }

  test("a refused request never echoes the secret or the token") {
    for {
      tuple <- application
      (served, _, _, _) = tuple
      refused <- served.run(postWith(exchange, "not-the-secret")).value
      refusedText <- body(refused.get)
      unknown <- served.run(introspect("token-never-issued")).value
      unknownText <- body(unknown.get)
    } yield {
      assertEquals(refused.get.status, Status.Unauthorized)
      assertEquals(field(refusedText, "error"), "invalid_client")
      assert(!refusedText.contains("s3cret"))
      assert(!refusedText.contains("not-the-secret"))
      assert(!refusedText.contains(recorded.code.value))
      assert(!unknownText.contains("token-never-issued"))
    }
  }

  test("a retired refresh token is refused and revokes its grant") {
    val renewal = Map("grant_type" -> "refresh_token", "client_id" -> clientId.value)
    for {
      tuple <- application
      (served, _, _, _) = tuple
      issued <- served.run(post(exchange)).value
      issuedText <- body(issued.get)
      presented = field(issuedText, "refresh_token")
      rotated <- served.run(post(renewal.updated("refresh_token", presented))).value
      rotatedText <- body(rotated.get)
      reused <- served.run(post(renewal.updated("refresh_token", presented))).value
      reusedText <- body(reused.get)
      after <- served.run(introspect(field(rotatedText, "access_token"))).value
      afterText <- body(after.get)
    } yield {
      assertEquals(rotated.get.status, Status.Ok)
      assertEquals(reused.get.status, Status.BadRequest)
      assertEquals(field(reusedText, "error"), "invalid_grant")
      assertEquals(member(afterText, "active"), Some(io.circe.Json.False))
    }
  }

  test("an unsupported grant type is refused without a token") {
    for {
      tuple <- application
      (served, _, _, _) = tuple
      answered <- served
        .run(post(Map("grant_type" -> "password", "client_id" -> clientId.value)))
        .value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.BadRequest)
      assertEquals(field(text, "error"), "unsupported_grant_type")
    }
  }

  test("a replayed client assertion is refused") {
    def assertion(jti: String): String = {
      val payload = Json.obj(
        "iss" -> Json.fromString(jwtId.value),
        "sub" -> Json.fromString(jwtId.value),
        "aud" -> Json.fromString(issuer.value),
        "exp" -> Json.fromLong(Start.plusSeconds(300L).getEpochSecond),
        "jti" -> Json.fromString(jti)
      )
      unsafe(Jws.sign(Alg.RS256, Fakes.keyId("key-1"), Fakes.signingPair.getPrivate, payload.noSpaces))
    }
    def asserted(jti: String): Request[IO] =
      Request[IO](
        method = Method.POST,
        uri = Uri.unsafeFromString(TokenUri),
        headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)),
        body = Stream
          .emits(
            Form
              .render(
                Map(
                  "grant_type" -> "client_credentials",
                  "client_id" -> jwtId.value,
                  "client_assertion" -> assertion(jti),
                  "client_assertion_type" -> ClientAssertion.Type
                )
              )
              .getBytes(StandardCharsets.UTF_8)
              .toSeq
          )
          .covary[IO]
      )
    for {
      tuple <- application
      (served, _, _, _) = tuple
      first <- served.run(asserted("assertion-1")).value
      second <- served.run(asserted("assertion-1")).value
      text <- body(second.get)
    } yield {
      assertEquals(first.get.status, Status.Ok)
      assertEquals(second.get.status, Status.Unauthorized)
      assertEquals(field(text, "error"), "invalid_client")
    }
  }

  test("a token minted for one resource is refused by another resource server") {
    def guard(moment: Ref[IO, Instant], audience: String): BearerGuard[IO] =
      new BearerGuard[IO](
        IO.pure(Right(Jwks(List(Fakes.signingJwk)))),
        issuer,
        new Clock[IO] { def instant: IO[Instant] = moment.get },
        Some(unsafe(Audience.from(audience)))
      )
    for {
      tuple <- application
      (served, moment, _, _) = tuple
      issued <- served
        .run(post(credentials.updated("resource", "https://api.example")))
        .value
      access <- body(issued.get).map(field(_, "access_token"))
      foreign <- guard(moment, "https://other.example")
        .verify(Some("Bearer " + access), unsafe(Scopes.parse("read")))
      accepted <- guard(moment, "https://api.example")
        .verify(Some("Bearer " + access), unsafe(Scopes.parse("read")))
    } yield {
      assertEquals(issued.get.status, Status.Ok)
      assertEquals(foreign.left.toOption.map(_.status), Some(401))
      assert(foreign.left.toOption.exists(_.header.contains("invalid_token")))
      assertEquals(accepted.toOption.map(_.audience.map(_.value)), Some(List("https://api.example")))
    }
  }
}
