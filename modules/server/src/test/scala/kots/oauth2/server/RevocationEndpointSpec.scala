package kots.oauth2.server

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

import cats.effect.IO
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.RevocationToken
import kots.oauth2.core.Subject
import kots.oauth2.core.TokenTypeHint
import kots.oauth2.store.Client
import kots.oauth2.store.Grant
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.memory.InMemoryClientStore
import kots.oauth2.store.memory.InMemoryGrantStore
import kots.oauth2.store.memory.InMemoryTokenStore
import munit.CatsEffectSuite

class RevocationEndpointSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val grant: GrantId = unsafe(GrantId.from("grant-1"))

  private def client: Client =
    Client(
      clientId,
      Set.empty,
      unsafe(kots.oauth2.core.Scopes.parse("read")),
      ClientAuthMethod.ClientSecretBasic,
      Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
    )

  private def basic(id: String, secret: String): Option[String] =
    Some(Base64.getEncoder.encodeToString(s"$id:$secret".getBytes(StandardCharsets.UTF_8)))

  private def token(access: String, refresh: Option[String], owner: ClientId = clientId): TokenRecord =
    TokenRecord(
      accessTokenHash =
        kots.oauth2.core.AccessTokenHash.of(unsafe(kots.oauth2.core.AccessToken.from(access))),
      refreshTokenHash =
        refresh.map(raw => kots.oauth2.core.RefreshTokenHash.of(unsafe(RefreshToken.from(raw)))),
      grantId = grant,
      clientId = owner,
      subject = unsafe(Subject.from("user-1")),
      scopes = unsafe(kots.oauth2.core.Scopes.parse("read")),
      details = kots.oauth2.core.AuthorizationDetails.empty,
      issuedAt = Start,
      accessExpiresAt = Start.plusSeconds(3600L),
      refreshExpiresAt = refresh.map(_ => Start.plusSeconds(7200L))
    )

  private def setup(
      records: List[TokenRecord] = List(token("at-1", Some("rt-1")))
  ): IO[(RevocationEndpoint[IO], InMemoryTokenStore[IO], InMemoryGrantStore[IO])] = {
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO.pure(Start)
    }
    for {
      tokens <- InMemoryTokenStore.create[IO](clock)
      _ <- records.foldLeft(IO.unit)((done, record) => done >> tokens.save(record))
      grants <- InMemoryGrantStore.create[IO]
      _ <- grants.save(
        Grant(
          grant,
          clientId,
          unsafe(Subject.from("user-1")),
          unsafe(kots.oauth2.core.Scopes.parse("read")),
          kots.oauth2.core.AuthorizationDetails.empty,
          revoked = false
        )
      )
      registry <- InMemoryClientStore.create[IO](List(client))
    } yield (
      new RevocationEndpoint[IO](new RegisteredClientAuthentication[IO](registry), tokens, grants),
      tokens,
      grants
    )
  }

  private def code(result: Either[OAuth2Error, Unit]): Option[String] =
    result.left.toOption.map(_.code)

  private def revoke(
      endpoint: RevocationEndpoint[IO],
      raw: String,
      hint: Option[String] = None
  ): IO[Either[OAuth2Error, Unit]] =
    endpoint(
      basic("client-1", "s3cret"),
      Map("client_id" -> "client-1") ++ hint.map("token_type_hint" -> _) ++ Map("token" -> raw)
    )

  test("a refresh token is revoked with its whole grant") {
    for {
      triple <- setup(List(token("at-1", Some("rt-1")), token("at-2", Some("rt-2"))))
      (endpoint, tokens, grants) = triple
      result <- revoke(endpoint, "rt-1", Some("refresh_token"))
      first <- tokens.findByAccess(unsafe(kots.oauth2.core.AccessToken.from("at-1")))
      second <- tokens.findByAccess(unsafe(kots.oauth2.core.AccessToken.from("at-2")))
      stored <- grants.find(grant)
    } yield {
      assertEquals(result, Right(()))
      assertEquals(first, None)
      assertEquals(second, None)
      assert(stored.exists(_.revoked))
    }
  }

  test("an access token is revoked alone and the grant survives") {
    for {
      triple <- setup(List(token("at-1", Some("rt-1")), token("at-2", Some("rt-2"))))
      (endpoint, tokens, grants) = triple
      result <- revoke(endpoint, "at-1", Some("access_token"))
      revoked <- tokens.findByAccess(unsafe(kots.oauth2.core.AccessToken.from("at-1")))
      kept <- tokens.findByAccess(unsafe(kots.oauth2.core.AccessToken.from("at-2")))
      stored <- grants.find(grant)
    } yield {
      assertEquals(result, Right(()))
      assertEquals(revoked, None)
      assert(kept.isDefined)
      assert(stored.exists(!_.revoked))
    }
  }

  test("a token without a hint is revoked as a refresh token") {
    for {
      triple <- setup()
      (endpoint, tokens, _) = triple
      result <- revoke(endpoint, "rt-1")
      byRefresh <- tokens.findByRefresh(unsafe(RefreshToken.from("rt-1")))
    } yield {
      assertEquals(result, Right(()))
      assertEquals(byRefresh, None)
    }
  }

  test("an unknown token is answered with success") {
    for {
      triple <- setup()
      (endpoint, _, _) = triple
      result <- revoke(endpoint, "absent")
    } yield assertEquals(result, Right(()))
  }

  test("a token of another client is answered with success and left alone") {
    for {
      triple <- setup(List(token("at-2", Some("rt-2"), unsafe(ClientId.from("client-2")))))
      (endpoint, tokens, _) = triple
      result <- revoke(endpoint, "rt-2")
      kept <- tokens.findByRefresh(unsafe(RefreshToken.from("rt-2")))
    } yield {
      assertEquals(result, Right(()))
      assert(kept.isDefined)
    }
  }

  test("a request without a token is refused with invalid_request") {
    for {
      triple <- setup()
      (endpoint, _, _) = triple
      result <- endpoint(basic("client-1", "s3cret"), Map("client_id" -> "client-1"))
    } yield assertEquals(code(result), Some("invalid_request"))
  }

  test("an unknown hint is refused with invalid_request") {
    for {
      triple <- setup()
      (endpoint, _, _) = triple
      result <- revoke(endpoint, "at-1", Some("id_token"))
    } yield assertEquals(code(result), Some("invalid_request"))
  }

  test("an unauthenticated client is refused with invalid_client") {
    for {
      triple <- setup()
      (endpoint, _, _) = triple
      result <- endpoint(basic("client-1", "wrong"), Map("token" -> "at-1", "client_id" -> "client-1"))
    } yield assertEquals(code(result), Some("invalid_client"))
  }

  test("a malformed basic header is refused with invalid_client") {
    for {
      triple <- setup()
      (endpoint, _, _) = triple
      result <- endpoint(Some("not base64 !"), Map("token" -> "at-1"))
    } yield assertEquals(code(result), Some("invalid_client"))
  }

  test("the token type hint is read from the request the endpoint takes") {
    assertEquals(TokenTypeHint.from("refresh_token").toOption, Some(TokenTypeHint.RefreshToken))
    assert(RevocationToken.from("at-1").isRight)
  }
}
