package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.atomic.AtomicInteger

import cats.effect.IO
import munit.CatsEffectSuite

class MigrationsSpec extends CatsEffectSuite {

  private val databases = new AtomicInteger(0)

  private def connect: IO[Connection] = {
    val name = s"migrations-${databases.get}"
    IO.blocking {
      Class.forName("org.h2.Driver")
      DriverManager.getConnection(s"jdbc:h2:mem:$name;DB_CLOSE_DELAY=-1")
    }
  }

  private def fresh(): Unit = {
    databases.incrementAndGet()
    ()
  }

  private val first: Migration = Migration(1, "CREATE TABLE one(id INT PRIMARY KEY)")

  private val second: Migration = Migration(2, "CREATE TABLE two(id INT PRIMARY KEY)")

  private def engine(steps: List[Migration]): Migrations[IO] =
    Migrations.of(connect, steps).toOption.get

  test("migrations are refused unless numbered contiguously from one") {
    assert(Migrations.of[IO](connect, List(second)).isLeft)
    assert(Migrations.of[IO](connect, List(first, first.copy(version = 3))).isLeft)
    assert(Migrations.of[IO](connect, List(first, second)).isRight)
  }

  test("applying records each version once and reapplying is idempotent") {
    fresh()
    val migrations = engine(List(first, second))
    for {
      before <- migrations.version
      applied <- migrations.apply
      after <- migrations.version
      again <- migrations.apply
      waiting <- migrations.pending
    } yield {
      assertEquals(before, 0)
      assertEquals(applied, Right(2))
      assertEquals(after, 2)
      assertEquals(again, Right(2))
      assertEquals(waiting, Nil)
    }
  }

  test("a changed script is detected by its recorded checksum") {
    fresh()
    for {
      _ <- engine(List(first)).apply
      verified <- engine(List(first.copy(script = "CREATE TABLE other(id INT)"))).verify
      intact <- engine(List(first, second)).verify
    } yield {
      assert(verified.isLeft)
      assertEquals(intact, Right(1))
    }
  }

  test("a database ahead of the known scripts is refused") {
    fresh()
    for {
      _ <- engine(List(first, second)).apply
      verified <- engine(List(first)).verify
    } yield assert(verified.isLeft)
  }

  test("a failing migration keeps the versions applied before it") {
    fresh()
    val broken = List(first, Migration(2, "CREATE BROKEN"))
    for {
      applied <- engine(broken).apply
      version <- engine(List(first)).version
      verified <- engine(List(first)).verify
    } yield {
      assert(applied.isLeft)
      assertEquals(version, 1)
      assertEquals(verified, Right(1))
    }
  }
}
