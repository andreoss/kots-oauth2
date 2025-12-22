package kots.oauth2.store.sql

import java.sql.Connection

import cats.effect.kernel.Resource
import cats.effect.kernel.Sync
import cats.syntax.flatMap._

import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.Wire
import kots.oauth2.store.Grant
import kots.oauth2.store.GrantStore

final class SqlGrantStore[F[_]: Sync] private (connect: F[Connection]) extends GrantStore[F] {

  def save(grant: Grant): F[Unit] = session { connection =>
    withTransaction(connection) {
      delete(connection, "DELETE FROM grant_details WHERE grant_id = ?", grant.id.value)
      delete(connection, "DELETE FROM grants WHERE grant_id = ?", grant.id.value)
      val insert = connection.prepareStatement(
        "INSERT INTO grants(grant_id, client_id, subject, scopes, revoked) VALUES(?, ?, ?, ?, ?)"
      )
      try {
        insert.setString(1, grant.id.value)
        insert.setString(2, grant.clientId.value)
        insert.setString(3, grant.subject.value)
        insert.setString(4, Wire[Scopes].encode(grant.scopes))
        insert.setBoolean(5, grant.revoked)
        insert.executeUpdate()
        ()
      } finally insert.close()
      DetailRows.insert(connection, "grant_details", "grant_id", grant.id.value, grant.details)
    }
  }

  def find(id: GrantId): F[Option[Grant]] = session { connection =>
    val select = connection.prepareStatement("SELECT * FROM grants WHERE grant_id = ?")
    try {
      select.setString(1, id.value)
      val results = select.executeQuery()
      if (results.next())
        Some(
          Grant(
            id = DetailRows.required(GrantId.from(results.getString("grant_id"))),
            clientId = DetailRows.required(ClientId.from(results.getString("client_id"))),
            subject = DetailRows.required(Subject.from(results.getString("subject"))),
            scopes = DetailRows.required(Wire[Scopes].decode(results.getString("scopes"))),
            details = DetailRows.read(connection, "grant_details", "grant_id", id.value),
            revoked = results.getBoolean("revoked")
          )
        )
      else None
    } finally select.close()
  }

  def revoke(id: GrantId): F[Unit] = session { connection =>
    val update = connection.prepareStatement("UPDATE grants SET revoked = TRUE WHERE grant_id = ?")
    try {
      update.setString(1, id.value)
      update.executeUpdate()
      ()
    } finally update.close()
  }

  private def delete(connection: Connection, sql: String, value: String): Unit = {
    val statement = connection.prepareStatement(sql)
    try {
      statement.setString(1, value)
      statement.executeUpdate()
      ()
    } finally statement.close()
  }

  private def withTransaction[A](connection: Connection)(work: => A): A = {
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

  private def session[A](use: Connection => A): F[A] =
    Resource
      .make(connect)(connection => Sync[F].blocking(connection.close()))
      .use(connection => Sync[F].blocking(use(connection)))
}

object SqlGrantStore {

  def create[F[_]: Sync](connect: F[Connection]): Either[String, F[SqlGrantStore[F]]] =
    Migrations
      .of(connect, Schema.migrations)
      .map(engine =>
        engine.apply.flatMap {
          case Left(reason) => Sync[F].raiseError(new IllegalStateException(reason))
          case Right(_)     => Sync[F].pure(new SqlGrantStore(connect))
        }
      )
}
