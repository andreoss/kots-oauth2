package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp

import cats.effect.kernel.Sync
import cats.syntax.flatMap._

import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.KeyId
import kots.oauth2.core.RequestUri
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.Wire
import kots.oauth2.jose.Jwk
import kots.oauth2.jose.Jwks
import kots.oauth2.store.AuditEvent
import kots.oauth2.store.AuditLog
import kots.oauth2.store.ConsentRecord
import kots.oauth2.store.ConsentStore
import kots.oauth2.store.KeyStore
import kots.oauth2.store.PushedRequest
import kots.oauth2.store.PushedRequestStore

final class SqlKeyStore[F[_]: Sync] private (connect: F[Connection])
    extends SqlSessions[F](connect)
    with KeyStore[F] {

  def jwks: F[Jwks] = session { connection =>
    Jwks(rows(connection, "SELECT kid, alg, params FROM server_keys ORDER BY seq"))
  }

  def current: F[Option[Jwk]] = session { connection =>
    rows(
      connection,
      "SELECT kid, alg, params FROM server_keys WHERE retired = FALSE ORDER BY seq DESC LIMIT 1"
    ).headOption
  }

  def find(kid: KeyId): F[Option[Jwk]] = session { connection =>
    val select = connection.prepareStatement("SELECT kid, alg, params FROM server_keys WHERE kid = ?")
    try {
      select.setString(1, kid.value)
      val results = select.executeQuery()
      if (results.next())
        Some(KeyRows.keyOf(results.getString(1), results.getString(2), results.getString(3)))
      else None
    } finally select.close()
  }

  def add(key: Jwk): F[Unit] = session { connection =>
    withTransaction(connection) {
      execute(connection, "DELETE FROM server_keys WHERE kid = ?", key.kid.value)
      val insert = connection.prepareStatement(
        "INSERT INTO server_keys(kid, alg, params, retired) VALUES(?, ?, ?, FALSE)"
      )
      try {
        insert.setString(1, key.kid.value)
        insert.setString(2, key.alg.value)
        insert.setString(3, KeyRows.encode(key))
        insert.executeUpdate()
        ()
      } finally insert.close()
    }
  }

  def retire(kid: KeyId): F[Unit] = session { connection =>
    execute(connection, "UPDATE server_keys SET retired = TRUE WHERE kid = ?", kid.value)
    ()
  }

  private def rows(connection: Connection, sql: String): List[Jwk] = {
    val statement = connection.createStatement()
    try {
      val results = statement.executeQuery(sql)
      Iterator
        .continually(results)
        .takeWhile(_.next())
        .map(entry => KeyRows.keyOf(entry.getString(1), entry.getString(2), entry.getString(3)))
        .toList
    } finally statement.close()
  }
}

object SqlKeyStore {

  def create[F[_]: Sync](connect: F[Connection]): Either[String, F[SqlKeyStore[F]]] =
    SqlSupportStores.bootstrapped(connect, new SqlKeyStore(connect))
}

final class SqlConsentStore[F[_]: Sync] private (connect: F[Connection])
    extends SqlSessions[F](connect)
    with ConsentStore[F] {

  def grant(record: ConsentRecord): F[Unit] = session { connection =>
    withTransaction(connection) {
      val merged = existing(connection, record.clientId, record.subject)
        .fold(record.scopes)(granted => Scopes.union(granted, record.scopes))
      execute(
        connection,
        "DELETE FROM consents WHERE client_id = ? AND subject = ?",
        record.clientId.value,
        record.subject.value
      )
      execute(
        connection,
        "INSERT INTO consents(client_id, subject, scopes) VALUES(?, ?, ?)",
        record.clientId.value,
        record.subject.value,
        Wire[Scopes].encode(merged)
      )
      ()
    }
  }

  def revoke(clientId: ClientId, subject: Subject): F[Unit] = session { connection =>
    execute(
      connection,
      "DELETE FROM consents WHERE client_id = ? AND subject = ?",
      clientId.value,
      subject.value
    )
    ()
  }

  def decide(clientId: ClientId, subject: Subject, scopes: Scopes): F[Boolean] = session { connection =>
    existing(connection, clientId, subject).exists(allowed => Scopes.isSubsetOf(scopes, allowed))
  }

  private def existing(connection: Connection, clientId: ClientId, subject: Subject): Option[Scopes] = {
    val select = connection.prepareStatement(
      "SELECT scopes FROM consents WHERE client_id = ? AND subject = ?"
    )
    try {
      select.setString(1, clientId.value)
      select.setString(2, subject.value)
      val results = select.executeQuery()
      if (results.next()) Some(DetailRows.required(Wire[Scopes].decode(results.getString(1)))) else None
    } finally select.close()
  }
}

object SqlConsentStore {

  def create[F[_]: Sync](connect: F[Connection]): Either[String, F[SqlConsentStore[F]]] =
    SqlSupportStores.bootstrapped(connect, new SqlConsentStore(connect))
}

final class SqlPushedRequestStore[F[_]: Sync] private (connect: F[Connection], clock: Clock[F])
    extends SqlSessions[F](connect)
    with PushedRequestStore[F] {

  def save(record: PushedRequest): F[Unit] = session { connection =>
    withTransaction(connection) {
      execute(connection, "DELETE FROM pushed_requests WHERE request_uri = ?", record.uri.value)
      val insert = connection.prepareStatement(
        "INSERT INTO pushed_requests(request_uri, client_id, parameters, expires_at) VALUES(?, ?, ?, ?)"
      )
      try {
        insert.setString(1, record.uri.value)
        insert.setString(2, record.clientId.value)
        insert.setString(3, DetailRows.encodeFields(record.parameters))
        insert.setTimestamp(4, Timestamp.from(record.expiresAt))
        insert.executeUpdate()
        ()
      } finally insert.close()
    }
  }

  def consume(uri: RequestUri): F[Option[PushedRequest]] =
    clock.instant.flatMap { now =>
      session { connection =>
        withTransaction(connection) {
          selectOne(connection, uri).flatMap { record =>
            val removed = execute(connection, "DELETE FROM pushed_requests WHERE request_uri = ?", uri.value)
            if (removed == 1 && !record.isExpired(now)) Some(record) else None
          }
        }
      }
    }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      session { connection =>
        val statement = connection.prepareStatement("DELETE FROM pushed_requests WHERE expires_at <= ?")
        try {
          statement.setTimestamp(1, Timestamp.from(now))
          statement.executeUpdate()
        } finally statement.close()
      }
    }

  private def selectOne(connection: Connection, uri: RequestUri): Option[PushedRequest] = {
    val select = connection.prepareStatement("SELECT * FROM pushed_requests WHERE request_uri = ?")
    try {
      select.setString(1, uri.value)
      val results = select.executeQuery()
      if (results.next())
        Some(
          PushedRequest(
            uri = DetailRows.required(RequestUri.from(results.getString("request_uri"))),
            clientId = DetailRows.required(ClientId.from(results.getString("client_id"))),
            parameters = DetailRows.decodeFields(results.getString("parameters")),
            expiresAt = results.getTimestamp("expires_at").toInstant
          )
        )
      else None
    } finally select.close()
  }
}

object SqlPushedRequestStore {

  def create[F[_]: Sync](
      connect: F[Connection],
      clock: Clock[F]
  ): Either[String, F[SqlPushedRequestStore[F]]] =
    SqlSupportStores.bootstrapped(connect, new SqlPushedRequestStore(connect, clock))
}

final class SqlAuditLog[F[_]: Sync] private (connect: F[Connection])
    extends SqlSessions[F](connect)
    with AuditLog[F] {

  def record(event: AuditEvent): F[Unit] = session { connection =>
    val insert = connection.prepareStatement(
      "INSERT INTO audit_events(name, client_id, subject, grant_id, active) VALUES(?, ?, ?, ?, ?)"
    )
    try {
      insert.setString(1, event.name)
      event match {
        case AuditEvent.Issued(clientId, subject, grantId) =>
          insert.setString(2, clientId.value)
          insert.setString(3, subject.value)
          insert.setString(4, grantId.value)
          insert.setNull(5, java.sql.Types.BOOLEAN)
        case AuditEvent.Refreshed(clientId, subject, grantId) =>
          insert.setString(2, clientId.value)
          insert.setString(3, subject.value)
          insert.setString(4, grantId.value)
          insert.setNull(5, java.sql.Types.BOOLEAN)
        case AuditEvent.Revoked(clientId, grantId) =>
          insert.setString(2, clientId.value)
          insert.setNull(3, java.sql.Types.VARCHAR)
          insert.setString(4, grantId.value)
          insert.setNull(5, java.sql.Types.BOOLEAN)
        case AuditEvent.Introspected(clientId, active) =>
          insert.setString(2, clientId.value)
          insert.setNull(3, java.sql.Types.VARCHAR)
          insert.setNull(4, java.sql.Types.VARCHAR)
          insert.setBoolean(5, active)
        case AuditEvent.AuthenticationFailed(clientId) =>
          optional(insert, 2, clientId.map(_.value))
          insert.setNull(3, java.sql.Types.VARCHAR)
          insert.setNull(4, java.sql.Types.VARCHAR)
          insert.setNull(5, java.sql.Types.BOOLEAN)
      }
      insert.executeUpdate()
      ()
    } finally insert.close()
  }

  def events: F[List[AuditEvent]] = session { connection =>
    val statement = connection.createStatement()
    try {
      val results = statement.executeQuery(
        "SELECT name, client_id, subject, grant_id, active FROM audit_events ORDER BY seq"
      )
      Iterator.continually(results).takeWhile(_.next()).map(eventOf).toList
    } finally statement.close()
  }

  private def eventOf(results: ResultSet): AuditEvent = {
    def client: ClientId = DetailRows.required(ClientId.from(results.getString("client_id")))
    def subject: Subject = DetailRows.required(Subject.from(results.getString("subject")))
    def grant: GrantId = DetailRows.required(GrantId.from(results.getString("grant_id")))
    results.getString("name") match {
      case "issued"       => AuditEvent.Issued(client, subject, grant)
      case "refreshed"    => AuditEvent.Refreshed(client, subject, grant)
      case "revoked"      => AuditEvent.Revoked(client, grant)
      case "introspected" => AuditEvent.Introspected(client, results.getBoolean("active"))
      case _              =>
        AuditEvent.AuthenticationFailed(
          Option(results.getString("client_id")).map(raw => DetailRows.required(ClientId.from(raw)))
        )
    }
  }
}

object SqlAuditLog {

  def create[F[_]: Sync](connect: F[Connection]): Either[String, F[SqlAuditLog[F]]] =
    SqlSupportStores.bootstrapped(connect, new SqlAuditLog(connect))
}

private[sql] object SqlSupportStores {

  def bootstrapped[F[_]: Sync, A](connect: F[Connection], store: => A): Either[String, F[A]] =
    Migrations
      .of(connect, Schema.migrations)
      .map(engine =>
        engine.apply.flatMap {
          case Left(reason) => Sync[F].raiseError(new IllegalStateException(reason))
          case Right(_)     => Sync[F].pure(store)
        }
      )
}
