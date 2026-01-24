package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

import cats.effect.IO
import cats.effect.Ref
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.GrantType
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RequestUri
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.jose.Fakes
import kots.oauth2.store.AuditEvent
import kots.oauth2.store.ConsentRecord
import kots.oauth2.store.PushedRequest
import munit.CatsEffectSuite

class SqlSupportStoresSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val databases = new AtomicInteger(0)

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private def connect: IO[Connection] = {
    val name = s"support-${databases.get}"
    IO.blocking {
      Class.forName("org.h2.Driver")
      DriverManager.getConnection(s"jdbc:h2:mem:$name;DB_CLOSE_DELAY=-1")
    }
  }

  override def beforeEach(context: BeforeEach): Unit = {
    databases.incrementAndGet()
    ()
  }

  test("keys publish in insertion order and rotation moves the current key") {
    for {
      store <- SqlKeyStore.create[IO](connect).toOption.get
      _ <- store.add(Fakes.rsa("key-1"))
      _ <- store.add(Fakes.ec("key-2"))
      _ <- store.retire(Fakes.rsa("key-1").kid)
      published <- store.jwks
      current <- store.current
      retiredFound <- store.find(Fakes.rsa("key-1").kid)
      _ <- store.retire(Fakes.ec("key-2").kid)
      exhausted <- store.current
    } yield {
      assertEquals(published.keys.map(_.kid.value), List("key-1", "key-2"))
      assertEquals(current.map(_.kid.value), Some("key-2"))
      assertEquals(retiredFound.map(_.kid.value), Some("key-1"))
      assertEquals(exhausted, None)
    }
  }

  test("re-adding a known key identifier replaces it and revives it") {
    for {
      store <- SqlKeyStore.create[IO](connect).toOption.get
      _ <- store.add(Fakes.rsa("key-1"))
      _ <- store.retire(Fakes.rsa("key-1").kid)
      _ <- store.add(Fakes.rsa("key-1"))
      current <- store.current
      published <- store.jwks
    } yield {
      assertEquals(current.map(_.kid.value), Some("key-1"))
      assertEquals(published.keys.size, 1)
    }
  }

  test("consents union across grants and decide by subset") {
    for {
      store <- SqlConsentStore.create[IO](connect).toOption.get
      _ <- store.grant(ConsentRecord(clientId, subject, unsafe(Scopes.parse("read"))))
      _ <- store.grant(ConsentRecord(clientId, subject, unsafe(Scopes.parse("write"))))
      allowed <- store.decide(clientId, subject, unsafe(Scopes.parse("read write")))
      denied <- store.decide(clientId, subject, unsafe(Scopes.parse("admin")))
      foreign <- store.decide(unsafe(ClientId.from("client-2")), subject, unsafe(Scopes.parse("read")))
      _ <- store.revoke(clientId, subject)
      revoked <- store.decide(clientId, subject, unsafe(Scopes.parse("read")))
    } yield {
      assertEquals(allowed, true)
      assertEquals(denied, false)
      assertEquals(foreign, false)
      assertEquals(revoked, false)
    }
  }

  test("a pushed request is consumed once and never after its lifetime") {
    val uri = unsafe(RequestUri.from("urn:ietf:params:oauth:request_uri:one"))
    val record = PushedRequest(
      uri,
      clientId,
      Map("response_type" -> "code", "scope" -> "read write"),
      Start.plusSeconds(60L)
    )
    for {
      moment <- Ref.of[IO, Instant](Start)
      clock = new Clock[IO] { def instant: IO[Instant] = moment.get }
      store <- SqlPushedRequestStore.create[IO](connect, clock).toOption.get
      _ <- store.save(record)
      first <- store.consume(uri)
      second <- store.consume(uri)
      _ <- store.save(record)
      _ <- moment.set(Start.plusSeconds(60L))
      expired <- store.consume(uri)
      _ <- store.save(record)
      swept <- store.sweep
    } yield {
      assertEquals(first, Some(record))
      assertEquals(second, None)
      assertEquals(expired, None)
      assertEquals(swept, 1)
    }
  }

  test("audit events read back in order with their fields") {
    val grant = unsafe(GrantId.from("grant-1"))
    val recorded = List(
      AuditEvent.Issued(clientId, subject, grant, GrantType.IdJag),
      AuditEvent.Refreshed(clientId, subject, grant),
      AuditEvent.Revoked(clientId, grant),
      AuditEvent.Introspected(clientId, active = true),
      AuditEvent.AuthenticationFailed(Some(clientId)),
      AuditEvent.AuthenticationFailed(None),
      AuditEvent.AssertionReplayed(clientId)
    )
    for {
      log <- SqlAuditLog.create[IO](connect).toOption.get
      _ <- recorded.foldLeft(IO.unit)((io, event) => io >> log.record(event))
      events <- log.events
    } yield assertEquals(events, recorded)
  }
}
