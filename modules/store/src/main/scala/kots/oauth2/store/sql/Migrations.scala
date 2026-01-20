package kots.oauth2.store.sql

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.sql.Connection

import cats.effect.kernel.Resource
import cats.effect.kernel.Sync
import cats.syntax.functor._

final case class Migration(version: Int, script: String) {
  def checksum: String =
    MessageDigest
      .getInstance("SHA-256")
      .digest(script.getBytes(StandardCharsets.UTF_8))
      .map(byte => f"$byte%02x")
      .mkString
}

final class Migrations[F[_]: Sync] private (connect: F[Connection], steps: List[Migration]) {

  def version: F[Int] = session { connection =>
    ensure(connection)
    recorded(connection).lastOption.fold(0)(_._1)
  }

  def pending: F[List[Migration]] = version.map(applied => steps.filter(_.version > applied))

  def verify: F[Either[String, Int]] = session { connection =>
    ensure(connection)
    checked(recorded(connection))
  }

  def apply: F[Either[String, Int]] = session { connection =>
    ensure(connection)
    checked(recorded(connection)) match {
      case Left(reason)   => Left(reason)
      case Right(applied) =>
        connection.setAutoCommit(false)
        try {
          steps.filter(_.version > applied).foreach { step =>
            record(connection, step)
            connection.commit()
          }
          Right(steps.lastOption.fold(applied)(_.version))
        } catch {
          case failure: java.sql.SQLException =>
            connection.rollback()
            Left(failure.getMessage)
        }
    }
  }

  private def checked(rows: List[(Int, String)]): Either[String, Int] = {
    val expected = steps.take(rows.size).map(step => step.version -> step.checksum)
    if (rows.size > steps.size) Left("more migrations are recorded than are known")
    else if (rows != expected) Left("the recorded migrations disagree with the known scripts")
    else Right(rows.lastOption.fold(0)(_._1))
  }

  private def record(connection: Connection, step: Migration): Unit = {
    step.script.split(';').map(_.trim).filter(_.nonEmpty).foreach { text =>
      val statement = connection.createStatement()
      try statement.execute(text)
      finally statement.close()
    }
    val insert = connection.prepareStatement(
      "INSERT INTO schema_version(version, checksum, applied_at) VALUES(?, ?, CURRENT_TIMESTAMP)"
    )
    try {
      insert.setInt(1, step.version)
      insert.setString(2, step.checksum)
      insert.executeUpdate()
      ()
    } finally insert.close()
  }

  private def ensure(connection: Connection): Unit = {
    val statement = connection.createStatement()
    try {
      statement.execute(
        "CREATE TABLE IF NOT EXISTS schema_version(" +
          "version INT PRIMARY KEY, checksum VARCHAR(64) NOT NULL, applied_at TIMESTAMP NOT NULL)"
      )
      ()
    } finally statement.close()
  }

  private def recorded(connection: Connection): List[(Int, String)] = {
    val statement = connection.createStatement()
    try {
      val results = statement.executeQuery("SELECT version, checksum FROM schema_version ORDER BY version")
      Iterator
        .continually(results)
        .takeWhile(_.next())
        .map(row => (row.getInt(1), row.getString(2)))
        .toList
    } finally statement.close()
  }

  private def session[A](use: Connection => A): F[A] =
    Resource
      .make(connect)(connection => Sync[F].blocking(connection.close()))
      .use(connection => Sync[F].blocking(use(connection)))
}

object Migrations {

  def of[F[_]: Sync](connect: F[Connection], steps: List[Migration]): Either[String, Migrations[F]] =
    Either.cond(
      steps.map(_.version) == (1 to steps.size).toList,
      new Migrations(connect, steps),
      "migrations must be numbered contiguously from one"
    )
}
