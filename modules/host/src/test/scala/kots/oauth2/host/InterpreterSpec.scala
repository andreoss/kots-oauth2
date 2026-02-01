package kots.oauth2.host

import java.nio.charset.StandardCharsets
import java.time.Instant

import cats.effect.IO
import cats.syntax.all._
import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.AuthorizationServerMetadata
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.Clock
import kots.oauth2.core.CodeChallenge
import kots.oauth2.core.CodeChallengeMethod
import kots.oauth2.core.CodeVerifier
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.Entropy
import kots.oauth2.core.Issuer
import kots.oauth2.core.LifetimePolicy
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Pkce
import kots.oauth2.core.ProtectedResourceMetadata
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.UserCode
import kots.oauth2.http.Endpoints
import kots.oauth2.http.Form
import kots.oauth2.http.Server
import kots.oauth2.jose.Fakes
import kots.oauth2.jose.Jwk
import kots.oauth2.server.AuthorizationEndpoint
import kots.oauth2.server.AuthorizationService
import kots.oauth2.server.DeviceAuthorizationEndpoint
import kots.oauth2.server.DeviceAuthorizationService
import kots.oauth2.server.SessionLogin
import kots.oauth2.server.IntrospectionEndpoint
import kots.oauth2.server.PushedAuthorizationEndpoint
import kots.oauth2.server.PushedAuthorizationService
import kots.oauth2.server.Readiness
import kots.oauth2.server.RegistrationEndpoint
import kots.oauth2.server.RegistrationService
import kots.oauth2.server.RegisteredClientAuthentication
import kots.oauth2.server.RevocationEndpoint
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
import kots.oauth2.store.memory.InMemoryKeyStore
import kots.oauth2.store.memory.InMemoryPushedRequestStore
import kots.oauth2.store.memory.InMemoryTokenStore
import fs2.Stream
import munit.CatsEffectSuite
import org.http4s.AuthScheme
import org.http4s.BasicCredentials
import org.http4s.Credentials
import org.http4s.Header
import org.http4s.Headers
import org.http4s.MediaType
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.Uri
import org.http4s.headers.Authorization
import org.http4s.headers.`Content-Type`
import org.typelevel.ci.CIString

class InterpreterSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

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

  private val metadata: AuthorizationServerMetadata = AuthorizationServerMetadata.of(
    unsafe(Issuer.from("https://server.example")),
    unsafe(EndpointUri.from("https://server.example/authorize")),
    unsafe(EndpointUri.from("https://server.example/token")),
    Some(unsafe(EndpointUri.from("https://server.example/revocation"))),
    Some(unsafe(EndpointUri.from("https://server.example/introspection"))),
    Some(unsafe(EndpointUri.from(s"https://server.example/${Endpoints.JwksPath}"))),
    unsafe(Scopes.parse("read"))
  )

  private val verification: EndpointUri = unsafe(EndpointUri.from("https://server.example/device"))

  private val resource: ProtectedResourceMetadata = ProtectedResourceMetadata(
    unsafe(ResourceIndicator.from("https://api.example")),
    List(unsafe(Issuer.from("https://server.example"))),
    unsafe(Scopes.parse("read"))
  )

  private val registered: Client = Client(
    clientId,
    Set(unsafe(RedirectUri.from("https://client.example/cb"))),
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private val mtlsId: ClientId = unsafe(ClientId.from("client-mtls"))

  private val mtlsClient: Client = Client(
    mtlsId,
    Set.empty,
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.SelfSignedTlsClientAuth,
    None,
    certificateThumbprint = Some(unsafe(CertificateThumbprint.from(Fakes.ClientCertificateThumbprint)))
  )

  private def wellKnown: Request[IO] =
    Request[IO](
      method = Method.GET,
      uri = Uri.unsafeFromString("http://localhost/.well-known/oauth-authorization-server")
    )

  private def jwks: Request[IO] =
    Request[IO](method = Method.GET, uri = Uri.unsafeFromString("http://localhost/jwks"))

  private def published: Jwk =
    Fakes.rsa("key-1")

  private def post(form: Map[String, String], secret: Option[String]): Request[IO] =
    postTo("/token", form, secret)

  private def postJson(path: String, payload: io.circe.Json): Request[IO] =
    Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString(s"http://localhost$path"),
      headers = Headers(`Content-Type`(MediaType.application.json)),
      body = Stream.emits(payload.noSpaces.getBytes(StandardCharsets.UTF_8).toSeq).covary[IO]
    )

  private def postTo(
      path: String,
      form: Map[String, String],
      secret: Option[String]
  ): Request[IO] =
    Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString(s"http://localhost$path"),
      headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
        Headers(secret.toList.map(value => Authorization(BasicCredentials(clientId.value, value)))),
      body = Stream.emits(Form.render(form).getBytes(StandardCharsets.UTF_8).toSeq).covary[IO]
    )

  private def application: IO[
    (org.http4s.HttpRoutes[IO], InMemoryDeviceStore[IO], SessionLogin[IO], InMemoryConsentStore[IO])
  ] = {
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
      _ <- codes.save(recorded)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
      devices <- InMemoryDeviceStore.create[IO](clock)
      keys <- InMemoryKeyStore.create[IO]
      _ <- keys.add(published)
      clients <- InMemoryClientStore.create[IO](List(registered, mtlsClient))
      consents <- InMemoryConsentStore.create[IO]
      login <- SessionLogin.create[IO]
      pushed <- InMemoryPushedRequestStore.create[IO](clock)
      authentication = new RegisteredClientAuthentication[IO](clients)
      authorization = new AuthorizationEndpoint[IO](
        clients,
        login,
        new AuthorizationService[IO](codes, consents, clock, entropy, LifetimePolicy.defaults),
        unsafe(Issuer.from("https://server.example")),
        Some(pushed)
      )
      par = new PushedAuthorizationEndpoint[IO](
        authentication,
        new PushedAuthorizationService[IO](pushed, clock, entropy, LifetimePolicy.defaults)
      )
      registration = new RegistrationEndpoint[IO](new RegistrationService[IO](clients, entropy))
      revocation = new RevocationEndpoint[IO](authentication, tokens, grants)
      introspection = new IntrospectionEndpoint[IO](authentication, tokens, grants)
      device = new DeviceAuthorizationEndpoint[IO](
        authentication,
        new DeviceAuthorizationService[IO](devices, clock, entropy, LifetimePolicy.defaults, verification)
      )
      limiter <- kots.oauth2.store.memory.InMemoryRateLimiter.create[IO](clock, 30, 60L)
      approval = new kots.oauth2.server.DeviceVerificationEndpoint[IO](devices, login, "form-secret")
    } yield (
      Interpreter.routes[IO](
        List(
          Server.authorize(authorization),
          Server.par(par),
          Server.register(registration),
          Server.registrationRead(registration),
          Server.registrationUpdate(registration),
          Server.registrationDelete(registration),
          Server.token(
            new TokenEndpoint[IO](
              authentication,
              new TokenService[IO](codes, tokens, grants, devices, clock, entropy, LifetimePolicy.defaults)
            )
          ),
          Server.revocation(revocation),
          Server.introspection(introspection),
          Server.deviceAuthorization(device),
          Server.verification(kots.oauth2.server.Throttle.verification(limiter, login, approval)),
          Server.verificationDecision(kots.oauth2.server.Throttle.verification(limiter, login, approval)),
          Server.metadata(metadata),
          Server.resourceMetadata(resource),
          Server.jwks(keys.jwks),
          Server.health[IO],
          Server.ready(
            new Readiness[IO](
              List(
                "clients" -> clients.find(clientId).map(_.isDefined),
                "keys" -> keys.jwks.map(_.keys.nonEmpty)
              )
            )
          )
        )
      ),
      devices,
      login,
      consents
    )
  }

  private def routes: IO[org.http4s.HttpRoutes[IO]] = application.map(_._1)

  private def cacheControl(response: Response[IO]): Option[String] =
    response.headers.headers.find(_.name.toString == Endpoints.CacheControlHeader).map(_.value)

  private def body(response: Response[IO]): IO[String] =
    response.body.compile.toVector.map(bytes => new String(bytes.toArray, StandardCharsets.UTF_8))

  private val session: kots.oauth2.server.SessionId =
    unsafe(kots.oauth2.server.SessionId.from("session-1"))

  private def formToken(text: String): String =
    "name=\"request_token\" value=\"([^\"]+)\"".r
      .findFirstMatchIn(text)
      .map(_.group(1))
      .getOrElse(sys.error(s"no request token in $text"))

  private def signed(request: Request[IO]): Request[IO] =
    request.addCookie(kots.oauth2.http.Endpoints.SessionCookie, session.value)

  private def field(text: String, name: String): String =
    io.circe.parser
      .parse(text)
      .toOption
      .flatMap(_.hcursor.get[String](name).toOption)
      .getOrElse(sys.error(s"no $name in $text"))

  private def member(text: String, name: String): Option[io.circe.Json] =
    io.circe.parser.parse(text).toOption.flatMap(_.hcursor.downField(name).focus)

  private def revoke(token: String, hint: String): Map[String, String] =
    Map("token" -> token, "token_type_hint" -> hint)

  private val exchange: Map[String, String] = Map(
    "grant_type" -> "authorization_code",
    "code" -> "code-1",
    "code_verifier" -> verifier.value,
    "client_id" -> clientId.value
  )

  test("a form post to the token endpoint is answered with a token") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Ok)
      assert(text.contains("access_token"))
      assert(text.contains("refresh_token"))
    }
  }

  test("a form post with a wrong secret is answered with unauthorized") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("wrong"))).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Unauthorized)
      assert(text.contains("invalid_client"))
    }
  }

  test("a refused client is answered with the challenge of the error model") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("wrong"))).value
      response = answered.get
    } yield assertEquals(
      response.headers.headers.find(_.name.toString == "WWW-Authenticate").map(_.value),
      Some(OAuth2Error.BasicChallenge)
    )
  }

  test("a malformed basic header is answered with unauthorized and the challenge") {
    for {
      served <- routes
      answered <- served
        .run(
          post(exchange, None).putHeaders(
            Header.Raw(CIString("Authorization"), "Basic not base64 !")
          )
        )
        .value
      response = answered.get
    } yield {
      assertEquals(response.status, Status.Unauthorized)
      assertEquals(
        response.headers.headers.find(_.name.toString == "WWW-Authenticate").map(_.value),
        Some(OAuth2Error.BasicChallenge)
      )
    }
  }

  test("a replayed code is answered with bad request") {
    for {
      served <- routes
      first <- served.run(post(exchange, Some("s3cret"))).value
      second <- served.run(post(exchange, Some("s3cret"))).value
      text <- body(second.get)
    } yield {
      assertEquals(first.get.status, Status.Ok)
      assertEquals(second.get.status, Status.BadRequest)
      assert(text.contains("invalid_grant"))
    }
  }

  test("an answered token is served with cache control no-store") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      response = answered.get
    } yield assertEquals(cacheControl(response), Some(Endpoints.NoStore))
  }

  test("a refused token is served with cache control no-store") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("wrong"))).value
      response = answered.get
    } yield assertEquals(cacheControl(response), Some(Endpoints.NoStore))
  }

  test("a revoked refresh token is answered with an empty success and refused afterwards") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      refresh <- body(answered.get).map(field(_, "refresh_token"))
      revoked <- served.run(postTo("/revocation", revoke(refresh, "refresh_token"), Some("s3cret"))).value
      text <- body(revoked.get)
      reused <- served
        .run(
          post(
            Map("grant_type" -> "refresh_token", "refresh_token" -> refresh, "client_id" -> clientId.value),
            Some("s3cret")
          )
        )
        .value
      refused <- body(reused.get)
    } yield {
      assertEquals(revoked.get.status, Status.Ok)
      assertEquals(text, "")
      assertEquals(reused.get.status, Status.BadRequest)
      assert(refused.contains("invalid_grant"))
    }
  }

  test("an unknown token is revoked with an empty success") {
    for {
      served <- routes
      answered <- served.run(postTo("/revocation", revoke("absent", "access_token"), Some("s3cret"))).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.Ok)
      assertEquals(text, "")
    }
  }

  test("revoking an access token invalidates the pair it was issued with") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      text <- body(answered.get)
      access = field(text, "access_token")
      refresh = field(text, "refresh_token")
      revoked <- served.run(postTo("/revocation", revoke(access, "access_token"), Some("s3cret"))).value
      reused <- served
        .run(
          post(
            Map("grant_type" -> "refresh_token", "refresh_token" -> refresh, "client_id" -> clientId.value),
            Some("s3cret")
          )
        )
        .value
    } yield {
      assertEquals(revoked.get.status, Status.Ok)
      assertEquals(reused.get.status, Status.BadRequest)
    }
  }

  test("revocation with a wrong secret is answered with unauthorized") {
    for {
      served <- routes
      answered <- served.run(postTo("/revocation", revoke("at-1", "access_token"), Some("wrong"))).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.Unauthorized)
      assert(text.contains("invalid_client"))
    }
  }

  test("a revoked token is served with cache control no-store") {
    for {
      served <- routes
      answered <- served.run(postTo("/revocation", revoke("absent", "access_token"), Some("s3cret"))).value
    } yield assertEquals(cacheControl(answered.get), Some(Endpoints.NoStore))
  }

  test("an issued access token is introspected as active with its metadata") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      issued <- body(answered.get).map(field(_, "access_token"))
      introspected <- served
        .run(postTo("/introspection", revoke(issued, "access_token"), Some("s3cret")))
        .value
      response = introspected.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Ok)
      assertEquals(member(text, "active"), Some(io.circe.Json.True))
      assertEquals(field(text, "client_id"), clientId.value)
      assertEquals(field(text, "scope"), "read")
      assertEquals(field(text, "token_type"), "Bearer")
    }
  }

  test("an unknown token is introspected as inactive") {
    for {
      served <- routes
      answered <- served.run(postTo("/introspection", revoke("absent", "access_token"), Some("s3cret"))).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Ok)
      assertEquals(member(text, "active"), Some(io.circe.Json.False))
      assert(!text.contains("client_id"))
    }
  }

  test("a revoked token is introspected as inactive") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      refresh <- body(answered.get).map(field(_, "refresh_token"))
      _ <- served.run(postTo("/revocation", revoke(refresh, "refresh_token"), Some("s3cret"))).value
      introspected <- served
        .run(postTo("/introspection", revoke(refresh, "refresh_token"), Some("s3cret")))
        .value
      text <- body(introspected.get)
    } yield assertEquals(member(text, "active"), Some(io.circe.Json.False))
  }

  test("introspection without credentials is answered with unauthorized") {
    for {
      served <- routes
      answered <- served.run(postTo("/introspection", revoke("at-1", "access_token"), None)).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Unauthorized)
      assert(text.contains("invalid_client"))
    }
  }

  test("an introspection answer is served with cache control no-store") {
    for {
      served <- routes
      answered <- served.run(postTo("/introspection", revoke("absent", "access_token"), Some("s3cret"))).value
    } yield assertEquals(cacheControl(answered.get), Some(Endpoints.NoStore))
  }

  test("liveness and readiness are served with their dependency reports") {
    for {
      served <- routes
      alive <- served
        .run(Request[IO](method = Method.GET, uri = Uri.unsafeFromString("http://localhost/health")))
        .value
      aliveText <- body(alive.get)
      ready <- served
        .run(Request[IO](method = Method.GET, uri = Uri.unsafeFromString("http://localhost/ready")))
        .value
      readyText <- body(ready.get)
      cursor = io.circe.parser.parse(readyText).toOption.get.hcursor
    } yield {
      assertEquals(alive.get.status, Status.Ok)
      assertEquals(field(aliveText, "status"), "ok")
      assertEquals(ready.get.status, Status.Ok)
      assertEquals(field(readyText, "status"), "ok")
      assertEquals(cursor.downField("dependencies").get[Boolean]("clients").toOption, Some(true))
      assertEquals(cursor.downField("dependencies").get[Boolean]("keys").toOption, Some(true))
    }
  }

  test("a failing dependency answers readiness as unavailable") {
    val degraded = Interpreter.routes[IO](
      List(
        Server.ready(
          new Readiness[IO](List("store" -> IO.raiseError[Boolean](new IllegalStateException("down"))))
        )
      )
    )
    for {
      answered <- degraded
        .run(Request[IO](method = Method.GET, uri = Uri.unsafeFromString("http://localhost/ready")))
        .value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.ServiceUnavailable)
      assertEquals(field(text, "status"), "unavailable")
    }
  }

  test("the protected resource document is served at its well known path") {
    for {
      served <- routes
      answered <- served
        .run(
          Request[IO](
            method = Method.GET,
            uri = Uri.unsafeFromString("http://localhost/.well-known/oauth-protected-resource")
          )
        )
        .value
      response = answered.get
      text <- body(response)
      cursor = io.circe.parser.parse(text).toOption.get.hcursor
    } yield {
      assertEquals(response.status, Status.Ok)
      assertEquals(cursor.get[String]("resource").toOption, Some("https://api.example"))
      assertEquals(
        cursor.get[List[String]]("authorization_servers").toOption,
        Some(List("https://server.example"))
      )
      assertEquals(cursor.get[List[String]]("scopes_supported").toOption, Some(List("read")))
      assertEquals(cacheControl(response), Some(Endpoints.PublicCache))
    }
  }

  test("the metadata document is served at the well known path") {
    for {
      served <- routes
      answered <- served.run(wellKnown).value
      response = answered.get
      text <- body(response)
      cursor = io.circe.parser.parse(text).toOption.get.hcursor
    } yield {
      assertEquals(response.status, Status.Ok)
      assertEquals(cursor.get[String]("issuer").toOption, Some("https://server.example"))
      assertEquals(
        cursor.get[String]("authorization_endpoint").toOption,
        Some("https://server.example/authorize")
      )
      assertEquals(cursor.get[String]("token_endpoint").toOption, Some("https://server.example/token"))
      assertEquals(
        cursor.get[String]("introspection_endpoint").toOption,
        Some("https://server.example/introspection")
      )
      assertEquals(cursor.get[String]("jwks_uri").toOption, Some("https://server.example/jwks"))
      assertEquals(cursor.get[List[String]]("scopes_supported").toOption, Some(List("read")))
      assertEquals(cursor.get[List[String]]("code_challenge_methods_supported").toOption, Some(List("S256")))
      assert(cursor.get[List[String]]("grant_types_supported").toOption.get.contains("refresh_token"))
    }
  }

  test("the metadata document is served with an explicit cache lifetime") {
    for {
      served <- routes
      answered <- served.run(wellKnown).value
    } yield assertEquals(cacheControl(answered.get), Some(Endpoints.PublicCache))
  }

  test("the key set is served at /jwks with the public parameters only") {
    for {
      served <- routes
      answered <- served.run(jwks).value
      response = answered.get
      text <- body(response)
      cursor = io.circe.parser.parse(text).toOption.get.hcursor
      keys = cursor.downField("keys").values.getOrElse(Nil).toVector
    } yield {
      assertEquals(response.status, Status.Ok)
      assertEquals(keys.length, 1)
      assertEquals(keys.head.hcursor.get[String]("kid").toOption, Some("key-1"))
      assertEquals(keys.head.hcursor.get[String]("kty").toOption, Some("RSA"))
      assertEquals(keys.head.hcursor.get[String]("alg").toOption, Some("RS256"))
      assertEquals(keys.head.hcursor.get[String]("use").toOption, Some("sig"))
      assertEquals(keys.head.hcursor.get[String]("n").toOption, Some(Fakes.Modulus))
      assertEquals(keys.head.hcursor.keys.map(_.toSet), Some(Set("kid", "kty", "alg", "use", "n", "e")))
    }
  }

  test("the key set is served with an explicit cache lifetime") {
    for {
      served <- routes
      answered <- served.run(jwks).value
    } yield assertEquals(cacheControl(answered.get), Some(Endpoints.PublicCache))
  }

  test("the key set is served with the jwk set media type") {
    for {
      served <- routes
      answered <- served.run(jwks).value
      declared = answered.get.headers.headers.find(_.name.toString == "Content-Type").map(_.value)
    } yield assert(declared.exists(_.startsWith(Endpoints.JwkSetMediaType)))
  }

  test("a failing document read is answered as a server error") {
    val failing =
      Interpreter.routes[IO](
        List(Server.jwks[IO](IO.raiseError[kots.oauth2.jose.Jwks](new RuntimeException("kaput"))))
      )
    for {
      answered <- failing.run(jwks).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.InternalServerError)
      assertEquals(cacheControl(response), Some(Endpoints.NoStore))
      assertEquals(field(text, "error"), "server_error")
    }
  }

  test("the authorization endpoint answers the full code flow end to end") {
    val user = unsafe(Subject.from("user-1"))
    val uri = "http://localhost/authorize?response_type=code" +
      s"&client_id=${clientId.value}" +
      "&redirect_uri=https%3A%2F%2Fclient.example%2Fcb" +
      "&scope=read&state=xyz" +
      s"&code_challenge=${challenge.value}&code_challenge_method=S256"
    for {
      tuple <- application
      (served, _, login, consents) = tuple
      _ <- consents.grant(ConsentRecord(clientId, user, unsafe(Scopes.parse("read"))))
      _ <- login.login(session, user)
      answered <- served
        .run(signed(Request[IO](method = Method.GET, uri = Uri.unsafeFromString(uri))))
        .value
      response = answered.get
      location = response.headers.headers.find(_.name.toString == "Location").map(_.value).get
      query = Form.parse(location.dropWhile(_ != '?').drop(1)).toOption.get
      exchanged <- served
        .run(
          post(
            Map(
              "grant_type" -> "authorization_code",
              "code" -> query("code"),
              "code_verifier" -> verifier.value,
              "client_id" -> clientId.value
            ),
            Some("s3cret")
          )
        )
        .value
      text <- body(exchanged.get)
    } yield {
      assertEquals(response.status, Status.Found)
      assert(location.startsWith("https://client.example/cb?"))
      assertEquals(query.get("state"), Some("xyz"))
      assertEquals(query.get("iss"), Some("https://server.example"))
      assertEquals(cacheControl(response), Some(Endpoints.NoStore))
      assertEquals(
        response.headers.headers.find(_.name.toString == Endpoints.ReferrerPolicyHeader).map(_.value),
        Some(Endpoints.NoReferrer)
      )
      assertEquals(exchanged.get.status, Status.Ok)
      assert(field(text, "access_token").nonEmpty)
    }
  }

  test("a registration is managed over http with its registration access token") {
    val payload = io.circe.Json.obj(
      "redirect_uris" -> io.circe.Json.arr(io.circe.Json.fromString("https://fresh.example/cb")),
      "scope" -> io.circe.Json.fromString("read")
    )
    def managed(method: Method, id: String, token: String, body: Option[io.circe.Json]): Request[IO] =
      Request[IO](
        method = method,
        uri = Uri.unsafeFromString(s"http://localhost/register/$id"),
        headers = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, token))) ++
          body.fold(Headers.empty)(_ => Headers(`Content-Type`(MediaType.application.json))),
        body = body.fold[fs2.Stream[IO, Byte]](Stream.empty)(json =>
          Stream.emits(json.noSpaces.getBytes(StandardCharsets.UTF_8).toSeq).covary[IO]
        )
      )
    for {
      served <- routes
      minted <- served.run(postJson("/register", payload)).value
      text <- body(minted.get)
      id = field(text, "client_id")
      token = field(text, "registration_access_token")
      read <- served.run(managed(Method.GET, id, token, None)).value
      readText <- body(read.get)
      updated <- served
        .run(
          managed(
            Method.PUT,
            id,
            token,
            Some(
              io.circe.Json.obj(
                "redirect_uris" -> io.circe.Json.arr(io.circe.Json.fromString("https://fresh.example/cb")),
                "scope" -> io.circe.Json.fromString("read write")
              )
            )
          )
        )
        .value
      updatedText <- body(updated.get)
      removed <- served.run(managed(Method.DELETE, id, token, None)).value
      afterwards <- served.run(managed(Method.GET, id, token, None)).value
    } yield {
      assertEquals(read.get.status, Status.Ok)
      assertEquals(field(readText, "scope"), "read")
      assertEquals(updated.get.status, Status.Ok)
      assertEquals(field(updatedText, "scope"), "read write")
      assertEquals(removed.get.status, Status.NoContent)
      assertEquals(afterwards.get.status, Status.Unauthorized)
    }
  }

  test("a registered client is minted over http and can use its credentials") {
    val payload = io.circe.Json.obj(
      "redirect_uris" -> io.circe.Json.arr(io.circe.Json.fromString("https://fresh.example/cb")),
      "token_endpoint_auth_method" -> io.circe.Json.fromString("client_secret_basic"),
      "scope" -> io.circe.Json.fromString("read")
    )
    for {
      served <- routes
      answered <- served.run(postJson("/register", payload)).value
      text <- body(answered.get)
      freshId = field(text, "client_id")
      freshSecret = field(text, "client_secret")
      issued <- served
        .run(
          Request[IO](
            method = Method.POST,
            uri = Uri.unsafeFromString("http://localhost/token"),
            headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
              Headers(List(Authorization(BasicCredentials(freshId, freshSecret)))),
            body = Stream
              .emits(
                Form
                  .render(Map("grant_type" -> "client_credentials", "client_id" -> freshId))
                  .getBytes(StandardCharsets.UTF_8)
                  .toSeq
              )
              .covary[IO]
          )
        )
        .value
      issuedText <- body(issued.get)
    } yield {
      assertEquals(answered.get.status, Status.Created)
      assert(freshId.nonEmpty)
      assert(freshSecret.nonEmpty)
      assertEquals(cacheControl(answered.get), Some(Endpoints.NoStore))
      assertEquals(issued.get.status, Status.Ok)
      assert(field(issuedText, "access_token").nonEmpty)
    }
  }

  test("a registration without a redirect uri is refused") {
    for {
      served <- routes
      answered <- served
        .run(postJson("/register", io.circe.Json.obj("scope" -> io.circe.Json.fromString("read"))))
        .value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.BadRequest)
      assertEquals(field(text, "error"), "invalid_redirect_uri")
    }
  }

  test("a pushed authorization request drives the code flow end to end") {
    val user = unsafe(Subject.from("user-1"))
    for {
      tuple <- application
      (served, _, login, consents) = tuple
      _ <- consents.grant(ConsentRecord(clientId, user, unsafe(Scopes.parse("read"))))
      _ <- login.login(session, user)
      parAnswer <- served
        .run(
          postTo(
            "/par",
            Map(
              "response_type" -> "code",
              "client_id" -> clientId.value,
              "redirect_uri" -> "https://client.example/cb",
              "scope" -> "read",
              "state" -> "xyz",
              "code_challenge" -> challenge.value,
              "code_challenge_method" -> "S256"
            ),
            Some("s3cret")
          )
        )
        .value
      parText <- body(parAnswer.get)
      requestUri = field(parText, "request_uri")
      authorized <- served
        .run(
          signed(
            Request[IO](
              method = Method.GET,
              uri = Uri.unsafeFromString(
                s"http://localhost/authorize?client_id=${clientId.value}&request_uri=" +
                  java.net.URLEncoder.encode(requestUri, "UTF-8")
              )
            )
          )
        )
        .value
      location = authorized.get.headers.headers.find(_.name.toString == "Location").map(_.value).get
      query = Form.parse(location.dropWhile(_ != '?').drop(1)).toOption.get
      exchanged <- served
        .run(
          post(
            Map(
              "grant_type" -> "authorization_code",
              "code" -> query("code"),
              "code_verifier" -> verifier.value,
              "client_id" -> clientId.value
            ),
            Some("s3cret")
          )
        )
        .value
      text <- body(exchanged.get)
    } yield {
      assertEquals(parAnswer.get.status, Status.Created)
      assert(requestUri.startsWith("urn:ietf:params:oauth:request_uri:"))
      assertEquals(authorized.get.status, Status.Found)
      assertEquals(query.get("state"), Some("xyz"))
      assertEquals(exchanged.get.status, Status.Ok)
      assert(field(text, "access_token").nonEmpty)
    }
  }

  test("an anonymous authorization is redirected back as access denied") {
    val uri = "http://localhost/authorize?response_type=code" +
      s"&client_id=${clientId.value}" +
      "&redirect_uri=https%3A%2F%2Fclient.example%2Fcb" +
      "&scope=read&state=xyz" +
      s"&code_challenge=${challenge.value}&code_challenge_method=S256"
    for {
      served <- routes
      answered <- served.run(Request[IO](method = Method.GET, uri = Uri.unsafeFromString(uri))).value
      response = answered.get
      location = response.headers.headers.find(_.name.toString == "Location").map(_.value).get
      query = Form.parse(location.dropWhile(_ != '?').drop(1)).toOption.get
    } yield {
      assertEquals(response.status, Status.Found)
      assertEquals(query.get("error"), Some("access_denied"))
      assertEquals(query.get("state"), Some("xyz"))
      assertEquals(query.get("iss"), Some("https://server.example"))
      assertEquals(query.get("code"), None)
    }
  }

  test("an access token is exchanged for an audience bound token") {
    for {
      served <- routes
      first <- served.run(post(exchange, Some("s3cret"))).value
      text <- body(first.get)
      subjectToken = field(text, "access_token")
      answered <- served
        .run(
          post(
            Map(
              "grant_type" -> "urn:ietf:params:oauth:grant-type:token-exchange",
              "subject_token" -> subjectToken,
              "subject_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
              "audience" -> "https://api.example",
              "client_id" -> clientId.value
            ),
            Some("s3cret")
          )
        )
        .value
      exchanged <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.Ok)
      assert(field(exchanged, "access_token").nonEmpty)
      assertEquals(field(exchanged, "issued_token_type"), "urn:ietf:params:oauth:token-type:access_token")
      assertEquals(field(exchanged, "token_type"), "Bearer")
    }
  }

  test("an exchange of an unknown subject token is refused") {
    for {
      served <- routes
      answered <- served
        .run(
          post(
            Map(
              "grant_type" -> "urn:ietf:params:oauth:grant-type:token-exchange",
              "subject_token" -> "absent",
              "subject_token_type" -> "urn:ietf:params:oauth:token-type:access_token",
              "client_id" -> clientId.value
            ),
            Some("s3cret")
          )
        )
        .value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.BadRequest)
      assertEquals(field(text, "error"), "invalid_grant")
    }
  }

  test("a device authorization is served with its codes and polling guidance") {
    for {
      pair <- application
      (served, _, _, _) = pair
      answered <- served
        .run(
          postTo(
            "/device_authorization",
            Map("client_id" -> clientId.value, "scope" -> "read"),
            Some("s3cret")
          )
        )
        .value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Ok)
      assert(field(text, "device_code").nonEmpty)
      assert(field(text, "user_code").contains("-"))
      assertEquals(field(text, "verification_uri"), verification.value)
      assertEquals(member(text, "expires_in"), Some(io.circe.Json.fromLong(1800L)))
      assertEquals(member(text, "interval"), Some(io.circe.Json.fromLong(5L)))
      assertEquals(cacheControl(response), Some(Endpoints.NoStore))
    }
  }

  test("a device poll is pending until the approval and then issues the tokens once") {
    def poll(code: String): Request[IO] =
      postTo(
        "/token",
        Map(
          "grant_type" -> "urn:ietf:params:oauth:grant-type:device_code",
          "device_code" -> code,
          "client_id" -> clientId.value
        ),
        Some("s3cret")
      )
    for {
      pair <- application
      (served, devices, _, _) = pair
      issued <- served
        .run(postTo("/device_authorization", Map("client_id" -> clientId.value), Some("s3cret")))
        .value
      text <- body(issued.get)
      code = field(text, "device_code")
      user = field(text, "user_code")
      pending <- served.run(poll(code)).value
      pendingText <- body(pending.get)
      hurried <- served.run(poll(code)).value
      hurriedText <- body(hurried.get)
      approved <- devices.approve(unsafe(UserCode.from(user)), unsafe(Subject.from("user-1")))
      answered <- served.run(poll(code)).value
      answeredText <- body(answered.get)
      replayed <- served.run(poll(code)).value
      replayedText <- body(replayed.get)
    } yield {
      assertEquals(pending.get.status, Status.BadRequest)
      assertEquals(field(pendingText, "error"), "authorization_pending")
      assertEquals(field(hurriedText, "error"), "slow_down")
      assertEquals(approved, true)
      assertEquals(answered.get.status, Status.Ok)
      assert(field(answeredText, "access_token").nonEmpty)
      assert(field(answeredText, "refresh_token").nonEmpty)
      assertEquals(field(replayedText, "error"), "invalid_grant")
    }
  }

  test("a forwarded client certificate authenticates the mutual tls client") {
    val request = Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString("http://localhost/token"),
      headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
        Headers(
          Header.Raw(
            CIString(Endpoints.ClientCertHeader),
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
    for {
      served <- routes
      answered <- served.run(request).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.Ok)
      assert(field(text, "access_token").nonEmpty)
    }
  }

  test("a certificate of another key is refused as invalid client") {
    val request = Request[IO](
      method = Method.POST,
      uri = Uri.unsafeFromString("http://localhost/token"),
      headers = Headers(`Content-Type`(MediaType.application.`x-www-form-urlencoded`)) ++
        Headers(
          Header.Raw(
            CIString(Endpoints.ClientCertHeader),
            java.net.URLEncoder.encode(Fakes.OtherCertificatePem, "UTF-8")
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
    for {
      served <- routes
      answered <- served.run(request).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.Unauthorized)
      assert(text.contains("invalid_client"))
    }
  }

  test("a flooded token endpoint answers too many requests with a retry hint") {
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
    val form = Map("grant_type" -> "client_credentials", "client_id" -> clientId.value)
    for {
      codes <- InMemoryCodeStore.create[IO](clock)
      tokens <- InMemoryTokenStore.create[IO](clock)
      grants <- InMemoryGrantStore.create[IO]
      devices <- InMemoryDeviceStore.create[IO](clock)
      clients <- InMemoryClientStore.create[IO](List(registered))
      limiter <- kots.oauth2.store.memory.InMemoryRateLimiter.create[IO](clock, 2, 60L)
      endpoint = new TokenEndpoint[IO](
        new RegisteredClientAuthentication[IO](clients),
        new TokenService[IO](codes, tokens, grants, devices, clock, entropy, LifetimePolicy.defaults)
      )
      served = Interpreter.routes[IO](
        List(Server.token(kots.oauth2.server.Throttle.token(limiter, endpoint)))
      )
      first <- served.run(post(form, Some("s3cret"))).value
      _ <- served.run(post(form, Some("s3cret"))).value
      third <- served.run(post(form, Some("s3cret"))).value
      text <- body(third.get)
    } yield {
      assertEquals(first.get.status, Status.Ok)
      assertEquals(third.get.status, Status.TooManyRequests)
      assertEquals(
        third.get.headers.headers.find(_.name.toString == Endpoints.RetryAfterHeader).map(_.value),
        Some("60")
      )
      assertEquals(cacheControl(third.get), Some(Endpoints.NoStore))
      assertEquals(field(text, "error"), "temporarily_unavailable")
    }
  }

  test("a request to another path is not served") {
    for {
      served <- routes
      answered <- served
        .run(Request[IO](method = Method.GET, uri = Uri.unsafeFromString("http://localhost/other")))
        .value
    } yield assertEquals(answered, None)
  }

  test("the token response renders expires_in as a number") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      text <- body(answered.get)
    } yield assert(member(text, "expires_in").exists(_.isNumber), text)
  }

  test("the device response renders expires_in and interval as numbers") {
    for {
      pair <- application
      (served, _, _, _) = pair
      answered <- served
        .run(postTo("/device_authorization", Map("client_id" -> clientId.value), Some("s3cret")))
        .value
      text <- body(answered.get)
    } yield {
      assert(member(text, "expires_in").exists(_.isNumber), text)
      assert(member(text, "interval").exists(_.isNumber), text)
    }
  }

  test("introspection renders active as a boolean") {
    for {
      served <- routes
      answered <- served.run(postTo("/introspection", revoke("absent", "access_token"), Some("s3cret"))).value
      text <- body(answered.get)
    } yield assert(member(text, "active").exists(_.isBoolean), text)
  }

  test("introspection renders exp, iat and nbf as numeric dates") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      issued <- body(answered.get).map(field(_, "access_token"))
      introspected <- served
        .run(postTo("/introspection", revoke(issued, "access_token"), Some("s3cret")))
        .value
      text <- body(introspected.get)
    } yield {
      assert(member(text, "exp").exists(_.isNumber), text)
      assert(member(text, "iat").exists(_.isNumber), text)
      assert(member(text, "nbf").exists(_.isNumber), text)
    }
  }

  test("the pushed authorization response renders expires_in as a number") {
    for {
      tuple <- application
      (served, _, _, _) = tuple
      answered <- served
        .run(
          postTo(
            "/par",
            Map(
              "response_type" -> "code",
              "client_id" -> clientId.value,
              "redirect_uri" -> "https://client.example/cb",
              "scope" -> "read",
              "state" -> "xyz",
              "code_challenge" -> challenge.value,
              "code_challenge_method" -> "S256"
            ),
            Some("s3cret")
          )
        )
        .value
      text <- body(answered.get)
    } yield assert(member(text, "expires_in").exists(_.isNumber), text)
  }

  test("a device authorization serves a client that authenticated without naming itself") {
    for {
      pair <- application
      (served, _, _, _) = pair
      answered <- served.run(postTo("/device_authorization", Map("scope" -> "read"), Some("s3cret"))).value
      response = answered.get
      text <- body(response)
    } yield {
      assertEquals(response.status, Status.Ok)
      assert(field(text, "device_code").nonEmpty, text)
    }
  }

  test("a body client id naming another client is refused at both endpoints") {
    for {
      pair <- application
      (served, _, _, _) = pair
      device <- served
        .run(postTo("/device_authorization", Map("client_id" -> "other-client"), Some("s3cret")))
        .value
      token <- served.run(post(exchange + ("client_id" -> "other-client"), Some("s3cret"))).value
    } yield {
      assertEquals(device.get.status, Status.Unauthorized)
      assertEquals(token.get.status, Status.Unauthorized)
    }
  }

  test("introspection answers the access token type whichever token was asked about") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      text <- body(answered.get)
      refresh = field(text, "refresh_token")
      introspected <- served
        .run(postTo("/introspection", revoke(refresh, "refresh_token"), Some("s3cret")))
        .value
      answer <- body(introspected.get)
    } yield {
      assertEquals(member(answer, "active"), Some(io.circe.Json.True), answer)
      assertEquals(member(answer, "token_type"), Some(io.circe.Json.fromString("Bearer")), answer)
    }
  }

  test("introspection names no resource owner for a grant that has none") {
    for {
      served <- routes
      granted <- served
        .run(postTo("/token", Map("grant_type" -> "client_credentials"), Some("s3cret")))
        .value
      text <- body(granted.get)
      access = field(text, "access_token")
      introspected <- served
        .run(postTo("/introspection", revoke(access, "access_token"), Some("s3cret")))
        .value
      answer <- body(introspected.get)
    } yield {
      assertEquals(member(answer, "active"), Some(io.circe.Json.True), answer)
      assertEquals(member(answer, "sub"), Some(io.circe.Json.fromString(clientId.value)), answer)
      assert(!answer.contains("username"), answer)
    }
  }

  test("introspection names the resource owner of a grant that has one") {
    for {
      served <- routes
      answered <- served.run(post(exchange, Some("s3cret"))).value
      text <- body(answered.get)
      access = field(text, "access_token")
      introspected <- served
        .run(postTo("/introspection", revoke(access, "access_token"), Some("s3cret")))
        .value
      answer <- body(introspected.get)
    } yield assert(answer.contains("username"), answer)
  }

  test("the verification address serves a page to whoever is signed in") {
    val user = unsafe(Subject.from("user-1"))
    val visit = Request[IO](method = Method.GET, uri = Uri.unsafeFromString("http://localhost/device"))
    for {
      pair <- application
      (served, _, login, _) = pair
      _ <- login.login(session, user)
      anonymous <- served.run(visit).value
      anonymousText <- body(anonymous.get)
      answered <- served.run(signed(visit)).value
      text <- body(answered.get)
    } yield {
      assertEquals(anonymous.get.status, Status.Ok)
      assert(anonymousText.contains("sign in first"), anonymousText)
      assertEquals(answered.get.status, Status.Ok)
      assert(text.contains("user_code"), text)
      assert(text.contains("form"), text)
    }
  }

  test("a user code typed at the verification address approves the pending device grant") {
    val user = unsafe(Subject.from("user-1"))
    for {
      pair <- application
      (served, _, login, _) = pair
      _ <- login.login(session, user)
      issued <- served
        .run(postTo("/device_authorization", Map("scope" -> "read"), Some("s3cret")))
        .value
      text <- body(issued.get)
      code = field(text, "device_code")
      entered = field(text, "user_code")
      confirm <- served
        .run(signed(postTo("/device", Map("user_code" -> entered), None)))
        .value
      confirmText <- body(confirm.get)
      token = formToken(confirmText)
      approved <- served
        .run(
          signed(
            postTo(
              "/device",
              Map("user_code" -> entered, "request_token" -> token, "approve" -> "yes"),
              None
            )
          )
        )
        .value
      polled <- served
        .run(
          postTo(
            "/token",
            Map("grant_type" -> "urn:ietf:params:oauth:grant-type:device_code", "device_code" -> code),
            Some("s3cret")
          )
        )
        .value
      granted <- body(polled.get)
    } yield {
      assertEquals(approved.get.status, Status.Ok)
      assertEquals(polled.get.status, Status.Ok)
      assert(field(granted, "access_token").nonEmpty, granted)
    }
  }

  test("an unknown user code is not approved") {
    val user = unsafe(Subject.from("user-1"))
    for {
      pair <- application
      (served, _, login, _) = pair
      _ <- login.login(session, user)
      answered <- served.run(signed(postTo("/device", Map("user_code" -> "ZZZZ-ZZZZ"), None))).value
      text <- body(answered.get)
    } yield {
      assertEquals(answered.get.status, Status.Ok)
      assert(text.contains("not approved"), text)
    }
  }

  test("a device grant is not approved by a caller that presented no session") {
    val user = unsafe(Subject.from("user-1"))
    for {
      pair <- application
      (served, _, login, _) = pair
      _ <- login.login(session, user)
      issued <- served
        .run(postTo("/device_authorization", Map("scope" -> "read"), Some("s3cret")))
        .value
      text <- body(issued.get)
      code = field(text, "device_code")
      entered = field(text, "user_code")
      approved <- served.run(postTo("/device", Map("user_code" -> entered), None)).value
      approvedText <- body(approved.get)
      polled <- served
        .run(
          postTo(
            "/token",
            Map("grant_type" -> "urn:ietf:params:oauth:grant-type:device_code", "device_code" -> code),
            Some("s3cret")
          )
        )
        .value
      answer <- body(polled.get)
    } yield {
      assert(!approvedText.contains("<p>approved</p>"), approvedText)
      assertEquals(polled.get.status, Status.BadRequest, answer)
      assertEquals(field(answer, "error"), "authorization_pending", answer)
    }
  }

  test("an approval carrying another session's request token is refused") {
    val user = unsafe(Subject.from("user-1"))
    for {
      pair <- application
      (served, _, login, _) = pair
      _ <- login.login(session, user)
      issued <- served
        .run(postTo("/device_authorization", Map("scope" -> "read"), Some("s3cret")))
        .value
      text <- body(issued.get)
      code = field(text, "device_code")
      entered = field(text, "user_code")
      forged <- served
        .run(
          signed(
            postTo(
              "/device",
              Map("user_code" -> entered, "request_token" -> "not-the-token", "approve" -> "yes"),
              None
            )
          )
        )
        .value
      forgedText <- body(forged.get)
      polled <- served
        .run(
          postTo(
            "/token",
            Map("grant_type" -> "urn:ietf:params:oauth:grant-type:device_code", "device_code" -> code),
            Some("s3cret")
          )
        )
        .value
      answer <- body(polled.get)
    } yield {
      assert(!forgedText.contains("<p>approved"), forgedText)
      assertEquals(field(answer, "error"), "authorization_pending", answer)
    }
  }

  test("the verification page names the client and the scope before approval") {
    val user = unsafe(Subject.from("user-1"))
    for {
      pair <- application
      (served, _, login, _) = pair
      _ <- login.login(session, user)
      issued <- served
        .run(postTo("/device_authorization", Map("scope" -> "read"), Some("s3cret")))
        .value
      text <- body(issued.get)
      entered = field(text, "user_code")
      confirm <- served.run(signed(postTo("/device", Map("user_code" -> entered), None))).value
      shown <- body(confirm.get)
    } yield {
      assert(shown.contains(clientId.value), shown)
      assert(shown.contains("read"), shown)
      assert(!shown.contains("<p>approved"), shown)
    }
  }

  test("repeated user code entry is refused for rate") {
    val user = unsafe(Subject.from("user-1"))
    for {
      pair <- application
      (served, _, login, _) = pair
      _ <- login.login(session, user)
      answers <- (1 to 60).toList.traverse(attempt =>
        served
          .run(signed(postTo("/device", Map("user_code" -> f"ZZZZ-ZZZ$attempt%01d"), None)))
          .value
          .map(_.map(_.status))
      )
    } yield assert(answers.exists(_.contains(Status.TooManyRequests)), answers.take(5).toString)
  }

  test("entry by a stranger does not spend what the signed in owner is allowed") {
    val user = unsafe(Subject.from("user-1"))
    for {
      pair <- application
      (served, _, login, _) = pair
      _ <- login.login(session, user)
      _ <- (1 to 60).toList.traverse(attempt =>
        served
          .run(
            postTo("/device", Map("user_code" -> f"ZZZZ-ZZZ$attempt%01d"), None)
              .addCookie(kots.oauth2.http.Endpoints.SessionCookie, "stranger")
          )
          .value
      )
      owner <- served.run(signed(postTo("/device", Map("user_code" -> "ZZZZ-ZZZZ"), None))).value
    } yield assertEquals(owner.map(_.status), Some(Status.Ok))
  }
}
