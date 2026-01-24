package kots.oauth2.server

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

import cats.effect.IO
import kots.oauth2.core.AccessToken
import kots.oauth2.core.AccessTokenHash
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.RefreshTokenHash
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.TokenTypeHint
import kots.oauth2.store.Client
import kots.oauth2.store.Grant
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.memory.InMemoryClientStore
import kots.oauth2.store.memory.InMemoryGrantStore
import kots.oauth2.store.memory.InMemoryTokenStore
import munit.CatsEffectSuite

class IntrospectionEndpointSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val grant: GrantId = unsafe(GrantId.from("grant-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val scopes: Scopes = unsafe(Scopes.parse("read"))

  private def client: Client =
    Client(
      clientId,
      Set.empty,
      scopes,
      ClientAuthMethod.ClientSecretBasic,
      Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
    )

  private def basic(id: String, secret: String): Option[String] =
    Some(Base64.getEncoder.encodeToString(s"$id:$secret".getBytes(StandardCharsets.UTF_8)))

  private def token(
      access: String,
      refresh: Option[String],
      owner: ClientId = clientId,
      accessExpiry: Instant = Start.plusSeconds(3600L),
      identifier: GrantId = grant
  ): TokenRecord =
    TokenRecord(
      accessTokenHash = AccessTokenHash.of(unsafe(AccessToken.from(access))),
      refreshTokenHash = refresh.map(raw => RefreshTokenHash.of(unsafe(RefreshToken.from(raw)))),
      grantId = identifier,
      clientId = owner,
      subject = subject,
      scopes = scopes,
      details = AuthorizationDetails.empty,
      issuedAt = Start,
      accessExpiresAt = accessExpiry,
      refreshExpiresAt = refresh.map(_ => Start.plusSeconds(7200L))
    )

  private def setup(
      records: List[TokenRecord] = List(token("at-1", Some("rt-1"))),
      revoked: Boolean = false
  ): IO[(IntrospectionEndpoint[IO], InMemoryGrantStore[IO])] = {
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO.pure(Start)
    }
    for {
      tokens <- InMemoryTokenStore.create[IO](clock)
      _ <- records.foldLeft(IO.unit)((done, record) => done >> tokens.save(record))
      grants <- InMemoryGrantStore.create[IO]
      _ <- grants.save(Grant(grant, clientId, subject, scopes, AuthorizationDetails.empty, revoked))
      registry <- InMemoryClientStore.create[IO](List(client))
    } yield (
      new IntrospectionEndpoint[IO](new RegisteredClientAuthentication[IO](registry), tokens, grants),
      grants
    )
  }

  private def code(result: Either[OAuth2Error, kots.oauth2.core.IntrospectionResponse]): Option[String] =
    result.left.toOption.map(_.code)

  private def introspect(
      endpoint: IntrospectionEndpoint[IO],
      raw: String,
      hint: Option[String] = None
  ): IO[Either[OAuth2Error, kots.oauth2.core.IntrospectionResponse]] =
    endpoint(
      basic("client-1", "s3cret"),
      Map("client_id" -> "client-1") ++ hint.map("token_type_hint" -> _) ++ Map("token" -> raw)
    )

  test("an access token of the caller is active with its metadata") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- introspect(endpoint, "at-1", Some("access_token"))
      body = kots.oauth2.http.IntrospectionDocument.render(result.toOption.get)
    } yield {
      assert(result.toOption.get.active)
      assertEquals(body("active"), io.circe.Json.True)
      assertEquals(body("client_id"), io.circe.Json.fromString("client-1"))
      assertEquals(body("username"), io.circe.Json.fromString("user-1"))
      assertEquals(body("sub"), io.circe.Json.fromString("user-1"))
      assertEquals(body("scope"), io.circe.Json.fromString("read"))
      assertEquals(body("token_type"), io.circe.Json.fromString("Bearer"))
      assertEquals(body("exp"), io.circe.Json.fromLong(Start.plusSeconds(3600L).getEpochSecond))
      assertEquals(body("iat"), io.circe.Json.fromLong(Start.getEpochSecond))
    }
  }

  test("a refresh token is active with its own expiry") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- introspect(endpoint, "rt-1", Some("refresh_token"))
      body = kots.oauth2.http.IntrospectionDocument.render(result.toOption.get)
    } yield {
      assertEquals(
        result.toOption.get.asInstanceOf[kots.oauth2.core.IntrospectionResponse.Active].kind,
        TokenTypeHint.RefreshToken
      )
      assertEquals(body("token_type"), io.circe.Json.fromString("Bearer"))
      assertEquals(body("exp"), io.circe.Json.fromLong(Start.plusSeconds(7200L).getEpochSecond))
    }
  }

  test("a token without a hint is introspected as a refresh token first") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      refresh <- introspect(endpoint, "rt-1")
      access <- introspect(endpoint, "at-1")
    } yield {
      assertEquals(
        refresh.toOption.get.asInstanceOf[kots.oauth2.core.IntrospectionResponse.Active].kind,
        TokenTypeHint.RefreshToken
      )
      assertEquals(
        kots.oauth2.http.IntrospectionDocument.render(access.toOption.get)("token_type"),
        io.circe.Json.fromString("Bearer")
      )
    }
  }

  test("a hint that does not match the token is answered as inactive") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- introspect(endpoint, "at-1", Some("refresh_token"))
    } yield {
      assert(!result.toOption.get.active)
    }
  }

  test("an unknown token is answered as inactive") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- introspect(endpoint, "absent")
    } yield {
      assert(!result.toOption.get.active)
    }
  }

  test("a token of another client is answered as inactive") {
    for {
      pair <- setup(List(token("at-2", Some("rt-2"), unsafe(ClientId.from("client-2")))))
      (endpoint, _) = pair
      result <- introspect(endpoint, "at-2", Some("access_token"))
    } yield assert(!result.toOption.get.active)
  }

  test("an expired access token is answered as inactive") {
    for {
      pair <- setup(List(token("at-1", Some("rt-1"), accessExpiry = Start)))
      (endpoint, _) = pair
      result <- introspect(endpoint, "at-1", Some("access_token"))
    } yield assert(!result.toOption.get.active)
  }

  test("a token of a revoked grant is answered as inactive") {
    for {
      pair <- setup(revoked = true)
      (endpoint, _) = pair
      result <- introspect(endpoint, "at-1", Some("access_token"))
    } yield assert(!result.toOption.get.active)
  }

  test("a token whose grant is unknown is answered as inactive") {
    for {
      pair <- setup(List(token("at-3", None, identifier = unsafe(GrantId.from("grant-9")))))
      (endpoint, _) = pair
      result <- introspect(endpoint, "at-3", Some("access_token"))
    } yield assert(!result.toOption.get.active)
  }

  test("a request without a token is refused with invalid_request") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- endpoint(basic("client-1", "s3cret"), Map("client_id" -> "client-1"))
    } yield assertEquals(code(result), Some("invalid_request"))
  }

  test("an unknown hint is refused with invalid_request") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- introspect(endpoint, "at-1", Some("id_token"))
    } yield assertEquals(code(result), Some("invalid_request"))
  }

  test("an unauthenticated caller is refused with invalid_client") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- endpoint(basic("client-1", "wrong"), Map("token" -> "at-1", "client_id" -> "client-1"))
    } yield assertEquals(code(result), Some("invalid_client"))
  }

  test("a caller without credentials is refused with invalid_client") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- endpoint(None, Map("token" -> "at-1"))
    } yield assertEquals(code(result), Some("invalid_client"))
  }

  test("a malformed basic header is refused with invalid_client") {
    for {
      pair <- setup()
      (endpoint, _) = pair
      result <- endpoint(Some("not base64 !"), Map("token" -> "at-1"))
    } yield assertEquals(code(result), Some("invalid_client"))
  }

  test("the introspected kind is one of the two registered hints") {
    assertEquals(TokenTypeHint.all.size, 2)
  }
}
