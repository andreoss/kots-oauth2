package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

import cats.effect.IO
import cats.effect.Ref
import kots.oauth2.core.AccessToken
import kots.oauth2.core.AccessTokenHash
import kots.oauth2.core.Action
import kots.oauth2.core.AuthorizationDetail
import kots.oauth2.core.AuthorizationDetailType
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.Audience
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.Location
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.RefreshTokenHash
import kots.oauth2.core.RevocationToken
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.TokenTypeHint
import kots.oauth2.store.TokenRecord
import munit.CatsEffectSuite

class SqlTokenStoreSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val databases = new AtomicInteger(0)

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val access: AccessToken = unsafe(AccessToken.from("at-1"))

  private val refresh: RefreshToken = unsafe(RefreshToken.from("rt-1"))

  private val grant: GrantId = unsafe(GrantId.from("grant-1"))

  private val details: AuthorizationDetails = AuthorizationDetails.of(
    List(
      AuthorizationDetail.of(
        unsafe(AuthorizationDetailType.from("payment")),
        List(unsafe(Location.from("https://api.example"))),
        List(unsafe(Action.from("read")), unsafe(Action.from("write"))),
        Map("max_amount" -> "10 eur")
      )
    )
  )

  private def record(
      token: AccessToken = access,
      rotating: Option[RefreshToken] = Some(refresh),
      grantId: GrantId = grant,
      accessExpiresAt: Instant = Start.plusSeconds(3600L),
      refreshExpiresAt: Option[Instant] = Some(Start.plusSeconds(7200L)),
      carried: AuthorizationDetails = details
  ): TokenRecord =
    TokenRecord(
      accessTokenHash = AccessTokenHash.of(token),
      refreshTokenHash = rotating.map(RefreshTokenHash.of),
      grantId = grantId,
      clientId = clientId,
      subject = unsafe(Subject.from("user-1")),
      scopes = unsafe(Scopes.parse("read write")),
      details = carried,
      issuedAt = Start,
      accessExpiresAt = accessExpiresAt,
      refreshExpiresAt = refreshExpiresAt,
      audience = Some(unsafe(Audience.from("https://api.example"))),
      actor = Some(unsafe(Subject.from("actor-1")))
    )

  private def setup: IO[(SqlTokenStore[IO], Ref[IO, Instant])] = {
    val name = s"tokens-${databases.incrementAndGet()}"
    val connect = IO.blocking {
      Class.forName("org.h2.Driver")
      DriverManager.getConnection(s"jdbc:h2:mem:$name;DB_CLOSE_DELAY=-1")
    }
    for {
      moment <- Ref.of[IO, Instant](Start)
      clock = new Clock[IO] { def instant: IO[Instant] = moment.get }
      store <- SqlTokenStore.create[IO](connect: IO[Connection], clock).toOption.get
    } yield (store, moment)
  }

  test("a saved record is found by its access and refresh tokens with every field") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record())
      byAccess <- store.findByAccess(access)
      byRefresh <- store.findByRefresh(refresh)
      absent <- store.findByAccess(unsafe(AccessToken.from("absent")))
    } yield {
      assertEquals(byAccess, Some(record()))
      assertEquals(byRefresh, Some(record()))
      assertEquals(absent, None)
    }
  }

  test("saving the same access hash replaces the record") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record())
      _ <- store.save(record(carried = AuthorizationDetails.empty))
      found <- store.findByAccess(access)
    } yield assertEquals(found.map(_.details), Some(AuthorizationDetails.empty))
  }

  test("an expired token is purged on lookup") {
    for {
      pair <- setup
      (store, moment) = pair
      _ <- store.save(record())
      _ <- moment.set(Start.plusSeconds(3600L))
      byAccess <- store.findByAccess(access)
      _ <- moment.set(Start.plusSeconds(7200L))
      byRefresh <- store.findByRefresh(refresh)
    } yield {
      assertEquals(byAccess, None)
      assertEquals(byRefresh, None)
    }
  }

  test("a retired refresh token is remembered with its grant") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record())
      _ <- store.retire(refresh, grant)
      gone <- store.findByRefresh(refresh)
      remembered <- store.rotated(refresh)
      unknown <- store.rotated(unsafe(RefreshToken.from("absent")))
    } yield {
      assertEquals(gone, None)
      assertEquals(remembered, Some(grant))
      assertEquals(unknown, None)
    }
  }

  test("revoking a refresh token answers the grant and drops its family") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record())
      _ <- store.save(
        record(token = unsafe(AccessToken.from("at-2")), rotating = None)
      )
      revoked <- store.revoke(
        unsafe(RevocationToken.from(refresh.value)),
        Some(TokenTypeHint.RefreshToken),
        clientId
      )
      sibling <- store.findByAccess(unsafe(AccessToken.from("at-2")))
      gone <- store.findByAccess(access)
    } yield {
      assertEquals(revoked, Some(grant))
      assertEquals(sibling, None)
      assertEquals(gone, None)
    }
  }

  test("revoking an access token drops only that record and answers no grant") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record())
      revoked <- store.revoke(
        unsafe(RevocationToken.from(access.value)),
        Some(TokenTypeHint.AccessToken),
        clientId
      )
      gone <- store.findByAccess(access)
    } yield {
      assertEquals(revoked, None)
      assertEquals(gone, None)
    }
  }

  test("a foreign client revokes nothing") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record())
      revoked <- store.revoke(
        unsafe(RevocationToken.from(refresh.value)),
        None,
        unsafe(ClientId.from("client-2"))
      )
      kept <- store.findByAccess(access)
    } yield {
      assertEquals(revoked, None)
      assertEquals(kept, Some(record()))
    }
  }

  test("an unhinted revocation prefers the refresh token") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record())
      revoked <- store.revoke(unsafe(RevocationToken.from(refresh.value)), None, clientId)
    } yield assertEquals(revoked, Some(grant))
  }

  test("revoking a grant drops every record of it") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record())
      _ <- store.save(record(token = unsafe(AccessToken.from("at-2")), rotating = None))
      _ <- store.save(
        record(
          token = unsafe(AccessToken.from("at-3")),
          rotating = None,
          grantId = unsafe(GrantId.from("grant-2"))
        )
      )
      _ <- store.revokeGrant(grant)
      gone <- store.findByAccess(access)
      other <- store.findByAccess(unsafe(AccessToken.from("at-3")))
    } yield {
      assertEquals(gone, None)
      assertEquals(other.map(_.grantId.value), Some("grant-2"))
    }
  }

  test("a sweep removes only records whose access and refresh are both spent") {
    for {
      pair <- setup
      (store, moment) = pair
      _ <- store.save(record())
      _ <- store.save(
        record(
          token = unsafe(AccessToken.from("at-2")),
          rotating = None,
          refreshExpiresAt = None,
          accessExpiresAt = Start.plusSeconds(60L)
        )
      )
      _ <- moment.set(Start.plusSeconds(3600L))
      swept <- store.sweep
      kept <- store.findByRefresh(refresh)
    } yield {
      assertEquals(swept, 1)
      assertEquals(kept, Some(record()))
    }
  }
}
