package dev.oauth2.store.memory

import java.time.Duration
import java.time.Instant

import cats.effect.IO
import dev.oauth2.core.ClientId
import dev.oauth2.core.Clock
import dev.oauth2.core.DeviceCode
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.core.TestClock
import dev.oauth2.core.UserCode
import dev.oauth2.store.DeviceRecord
import munit.CatsEffectSuite

class MemoryDeviceStoreSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def clockOf(test: TestClock): Clock[IO] =
    new Clock[IO] {
      def instant: IO[Instant] = IO(test.instant)
    }

  private val device: DeviceCode = unsafe(DeviceCode.from("device-1"))

  private val user: UserCode = unsafe(UserCode.from("BCDF-GHJK"))

  private val other: UserCode = unsafe(UserCode.from("MNPQ-RSTV"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private def record(expiresAt: Instant): DeviceRecord =
    DeviceRecord(
      deviceCode = device,
      userCode = user,
      clientId = unsafe(ClientId.from("client-1")),
      scopes = unsafe(Scopes.parse("read")),
      expiresAt = expiresAt,
      subject = None,
      denied = false,
      lastPolledAt = None
    )

  private def store(expiresAt: Instant): IO[InMemoryDeviceStore[IO]] = {
    val clock = clockOf(new TestClock(start, Duration.ofSeconds(1L)))
    InMemoryDeviceStore.create[IO](clock).flatMap(devices => devices.save(record(expiresAt)).as(devices))
  }

  test("a saved record is polled back and the poll instant is recorded") {
    for {
      devices <- store(start.plusSeconds(600L))
      first <- devices.poll(device)
      second <- devices.poll(device)
    } yield {
      assertEquals(first.flatMap(_.lastPolledAt), None)
      assertEquals(second.flatMap(_.lastPolledAt), Some(start))
    }
  }

  test("an approval is recorded once and every later decision is refused") {
    for {
      devices <- store(start.plusSeconds(600L))
      approved <- devices.approve(user, subject)
      again <- devices.approve(user, subject)
      denied <- devices.deny(user)
      polled <- devices.poll(device)
    } yield {
      assertEquals(approved, true)
      assertEquals(again, false)
      assertEquals(denied, false)
      assertEquals(polled.flatMap(_.subject), Some(subject))
      assertEquals(polled.map(_.denied), Some(false))
    }
  }

  test("a denial is recorded once and an approval afterwards is refused") {
    for {
      devices <- store(start.plusSeconds(600L))
      denied <- devices.deny(user)
      approved <- devices.approve(user, subject)
      polled <- devices.poll(device)
    } yield {
      assertEquals(denied, true)
      assertEquals(approved, false)
      assertEquals(polled.map(_.denied), Some(true))
    }
  }

  test("an unknown or expired user code cannot be decided") {
    for {
      fresh <- store(start.plusSeconds(600L))
      unknown <- fresh.approve(other, subject)
      expired <- store(start)
      late <- expired.approve(user, subject)
    } yield {
      assertEquals(unknown, false)
      assertEquals(late, false)
    }
  }

  test("a consumed record is taken exactly once") {
    for {
      devices <- store(start.plusSeconds(600L))
      first <- devices.consume(device)
      second <- devices.consume(device)
      polled <- devices.poll(device)
    } yield {
      assertEquals(first.map(_.deviceCode), Some(device))
      assertEquals(second, None)
      assertEquals(polled, None)
    }
  }

  test("an expired record consumes to nothing") {
    for {
      devices <- store(start)
      taken <- devices.consume(device)
      polled <- devices.poll(device)
    } yield {
      assertEquals(taken, None)
      assertEquals(polled, None)
    }
  }
}
