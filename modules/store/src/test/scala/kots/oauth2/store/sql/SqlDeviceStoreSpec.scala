package kots.oauth2.store.sql

import java.sql.DriverManager
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

import cats.effect.IO
import cats.effect.Ref
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.DeviceCode
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.UserCode
import kots.oauth2.store.DeviceRecord
import kots.oauth2.store.memory.InMemoryDeviceStore
import munit.CatsEffectSuite

class SqlDeviceStoreSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val databases = new AtomicInteger(0)

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val device: DeviceCode = unsafe(DeviceCode.from("device-1"))

  private val user: UserCode = unsafe(UserCode.from("ABCD-EFGH"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val record: DeviceRecord = DeviceRecord(
    deviceCode = device,
    userCode = user,
    clientId = unsafe(ClientId.from("client-1")),
    scopes = unsafe(Scopes.parse("read")),
    expiresAt = Start.plusSeconds(1800L),
    subject = None,
    denied = false,
    lastPolledAt = None,
    resource = Some(unsafe(ResourceIndicator.from("https://api.example")))
  )

  private def setup: IO[(SqlDeviceStore[IO], Ref[IO, Instant])] = {
    val name = s"devices-${databases.incrementAndGet()}"
    val connect = IO.blocking {
      Class.forName("org.h2.Driver")
      DriverManager.getConnection(s"jdbc:h2:mem:$name;DB_CLOSE_DELAY=-1")
    }
    for {
      moment <- Ref.of[IO, Instant](Start)
      clock = new Clock[IO] { def instant: IO[Instant] = moment.get }
      store <- SqlDeviceStore.create[IO](connect, clock).toOption.get
    } yield (store, moment)
  }

  test("a poll answers the record and remembers the polling moment") {
    for {
      pair <- setup
      (store, moment) = pair
      _ <- store.save(record)
      first <- store.poll(device)
      _ <- moment.set(Start.plusSeconds(1L))
      second <- store.poll(device)
      absent <- store.poll(unsafe(DeviceCode.from("absent")))
    } yield {
      assertEquals(first, Some(record))
      assertEquals(second.flatMap(_.lastPolledAt), Some(Start))
      assertEquals(absent, None)
    }
  }

  test("an approval decides once and only while undecided and alive") {
    for {
      pair <- setup
      (store, moment) = pair
      _ <- store.save(record)
      approved <- store.approve(user, subject)
      again <- store.approve(user, subject)
      polled <- store.poll(device)
      _ <- moment.set(Start.plusSeconds(1800L))
      late <- store.approve(unsafe(UserCode.from("WXYZ-WXYZ")), subject)
    } yield {
      assertEquals(approved, true)
      assertEquals(again, false)
      assertEquals(polled.flatMap(_.subject), Some(subject))
      assertEquals(late, false)
    }
  }

  test("a denial decides the code and an approval cannot follow") {
    for {
      pair <- setup
      (store, _) = pair
      _ <- store.save(record)
      denied <- store.deny(user)
      approved <- store.approve(user, subject)
      polled <- store.poll(device)
    } yield {
      assertEquals(denied, true)
      assertEquals(approved, false)
      assertEquals(polled.map(_.denied), Some(true))
    }
  }

  test("a consume is single use and refuses an expired code") {
    for {
      pair <- setup
      (store, moment) = pair
      _ <- store.save(record)
      first <- store.consume(device)
      second <- store.consume(device)
      _ <- store.save(record)
      _ <- moment.set(Start.plusSeconds(1800L))
      expired <- store.consume(device)
    } yield {
      assertEquals(first, Some(record))
      assertEquals(second, None)
      assertEquals(expired, None)
    }
  }

  test("a sweep removes only the expired records") {
    for {
      pair <- setup
      (store, moment) = pair
      _ <- store.save(record)
      _ <- store.save(
        record.copy(
          deviceCode = unsafe(DeviceCode.from("device-2")),
          userCode = unsafe(UserCode.from("IJKL-MNOP")),
          expiresAt = Start.plusSeconds(60L)
        )
      )
      _ <- moment.set(Start.plusSeconds(60L))
      swept <- store.sweep
      kept <- store.poll(device)
    } yield {
      assertEquals(swept, 1)
      assert(kept.isDefined)
    }
  }

  test("an expired record beside a live one leaves both stores naming the live one") {
    val expired = record.copy(
      deviceCode = unsafe(DeviceCode.from("device-0")),
      expiresAt = Start.plusSeconds(1L)
    )
    for {
      pair <- setup
      (store, moment) = pair
      memory <- InMemoryDeviceStore.create[IO](new Clock[IO] { def instant: IO[Instant] = moment.get })
      _ <- store.save(expired)
      _ <- memory.save(expired)
      _ <- store.save(record)
      _ <- memory.save(record)
      _ <- moment.set(Start.plusSeconds(2L))
      relational <- store.pending(user)
      inMemory <- memory.pending(user)
    } yield {
      assertEquals(inMemory.map(_.deviceCode), Some(device))
      assertEquals(relational, inMemory)
    }
  }
}
