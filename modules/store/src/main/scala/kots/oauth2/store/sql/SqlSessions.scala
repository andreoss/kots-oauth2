package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.PreparedStatement

import cats.effect.kernel.Resource
import cats.effect.kernel.Sync

private[sql] abstract class SqlSessions[F[_]: Sync](connect: F[Connection]) {

  protected def session[A](use: Connection => A): F[A] =
    Resource
      .make(connect)(connection => Sync[F].blocking(connection.close()))
      .use(connection => Sync[F].blocking(use(connection)))

  protected def withTransaction[A](connection: Connection)(work: => A): A = {
    connection.setAutoCommit(false)
    scala.util.Try(work) match {
      case scala.util.Success(outcome) =>
        connection.commit()
        outcome
      case failure @ scala.util.Failure(_) =>
        connection.rollback()
        failure.get
    }
  }

  protected def execute(connection: Connection, sql: String, values: String*): Int = {
    val statement = connection.prepareStatement(sql)
    try {
      values.zipWithIndex.foreach { case (value, index) => statement.setString(index + 1, value) }
      statement.executeUpdate()
    } finally statement.close()
  }

  protected def update(connection: Connection, sql: String, values: String*): Unit = {
    execute(connection, sql, values: _*)
    ()
  }

  protected def optional(statement: PreparedStatement, index: Int, value: Option[String]): Unit =
    value match {
      case Some(present) => statement.setString(index, present)
      case None          => statement.setNull(index, java.sql.Types.VARCHAR)
    }
}
