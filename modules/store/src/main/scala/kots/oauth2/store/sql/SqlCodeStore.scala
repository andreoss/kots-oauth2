package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp

import cats.effect.kernel.Sync
import cats.syntax.flatMap._

import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.CodeChallenge
import kots.oauth2.core.CodeChallengeMethod
import kots.oauth2.core.GrantId
import kots.oauth2.core.Pkce
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.Wire
import kots.oauth2.store.CodeRecord
import kots.oauth2.store.CodeStore

final class SqlCodeStore[F[_]: Sync] private (connect: F[Connection], clock: Clock[F])
    extends SqlSessions[F](connect)
    with CodeStore[F] {

  def save(record: CodeRecord): F[Unit] = session { connection =>
    withTransaction(connection) {
      update(connection, "DELETE FROM code_details WHERE code = ?", record.code.value)
      update(connection, "DELETE FROM codes WHERE code = ?", record.code.value)
      insertRecord(connection, record)
    }
  }

  def consume(code: AuthorizationCode): F[Option[CodeRecord]] =
    clock.instant.flatMap { now =>
      session { connection =>
        withTransaction(connection) {
          selectOne(connection, code).flatMap { record =>
            val removal = connection.prepareStatement("DELETE FROM codes WHERE code = ?")
            val removed =
              try {
                removal.setString(1, code.value)
                removal.executeUpdate()
              } finally removal.close()
            update(connection, "DELETE FROM code_details WHERE code = ?", code.value)
            if (removed == 1 && !record.isExpired(now)) Some(record) else None
          }
        }
      }
    }

  def redeem(code: AuthorizationCode, grant: GrantId): F[Unit] = session { connection =>
    withTransaction(connection) {
      update(connection, "DELETE FROM redeemed_codes WHERE code = ?", code.value)
      val insert = connection.prepareStatement(
        "INSERT INTO redeemed_codes(code, grant_id) VALUES(?, ?)"
      )
      try {
        insert.setString(1, code.value)
        insert.setString(2, grant.value)
        insert.executeUpdate()
        ()
      } finally insert.close()
    }
  }

  def redeemed(code: AuthorizationCode): F[Option[GrantId]] = session { connection =>
    val select = connection.prepareStatement("SELECT grant_id FROM redeemed_codes WHERE code = ?")
    try {
      select.setString(1, code.value)
      val results = select.executeQuery()
      if (results.next()) Some(DetailRows.required(GrantId.from(results.getString(1)))) else None
    } finally select.close()
  }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      session { connection =>
        val moment = Timestamp.from(now)
        val details = connection.prepareStatement(
          "DELETE FROM code_details WHERE code IN (SELECT code FROM codes WHERE expires_at <= ?)"
        )
        try {
          details.setTimestamp(1, moment)
          details.executeUpdate()
        } finally details.close()
        val codes = connection.prepareStatement("DELETE FROM codes WHERE expires_at <= ?")
        try {
          codes.setTimestamp(1, moment)
          codes.executeUpdate()
        } finally codes.close()
      }
    }

  private def insertRecord(connection: Connection, record: CodeRecord): Unit = {
    val insert = connection.prepareStatement(
      "INSERT INTO codes(code, client_id, redirect_uri, subject, scopes, challenge, " +
        "challenge_method, expires_at, resource) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    try {
      insert.setString(1, record.code.value)
      insert.setString(2, record.clientId.value)
      insert.setString(3, record.redirectUri.value)
      insert.setString(4, record.subject.value)
      insert.setString(5, Wire[Scopes].encode(record.scopes))
      optional(insert, 6, record.pkce.map(_.challenge.value))
      optional(insert, 7, record.pkce.map(_.method.value))
      insert.setTimestamp(8, Timestamp.from(record.expiresAt))
      optional(insert, 9, record.resource.map(_.value))
      insert.executeUpdate()
      ()
    } finally insert.close()
    DetailRows.insert(connection, "code_details", "code", record.code.value, record.details)
  }

  private def selectOne(connection: Connection, code: AuthorizationCode): Option[CodeRecord] = {
    val select = connection.prepareStatement("SELECT * FROM codes WHERE code = ?")
    try {
      select.setString(1, code.value)
      val results = select.executeQuery()
      if (results.next()) Some(row(connection, results)) else None
    } finally select.close()
  }

  private def row(connection: Connection, results: ResultSet): CodeRecord =
    CodeRecord(
      code = DetailRows.required(AuthorizationCode.from(results.getString("code"))),
      clientId = DetailRows.required(ClientId.from(results.getString("client_id"))),
      redirectUri = DetailRows.required(RedirectUri.from(results.getString("redirect_uri"))),
      subject = DetailRows.required(Subject.from(results.getString("subject"))),
      scopes = DetailRows.required(Wire[Scopes].decode(results.getString("scopes"))),
      details = DetailRows.read(connection, "code_details", "code", results.getString("code")),
      pkce = Option(results.getString("challenge")).map(challenge =>
        Pkce(
          DetailRows.required(CodeChallenge.from(challenge)),
          DetailRows.required(CodeChallengeMethod.from(results.getString("challenge_method")))
        )
      ),
      expiresAt = results.getTimestamp("expires_at").toInstant,
      resource =
        Option(results.getString("resource")).map(value => DetailRows.required(ResourceIndicator.from(value)))
    )

}

object SqlCodeStore {

  def create[F[_]: Sync](
      connect: F[Connection],
      clock: Clock[F]
  ): Either[String, F[SqlCodeStore[F]]] =
    Migrations
      .of(connect, Schema.migrations)
      .map(engine =>
        engine.apply.flatMap {
          case Left(reason) => Sync[F].raiseError(new IllegalStateException(reason))
          case Right(_)     => Sync[F].pure(new SqlCodeStore(connect, clock))
        }
      )
}
