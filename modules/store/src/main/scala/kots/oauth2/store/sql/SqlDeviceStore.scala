package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Timestamp

import cats.effect.kernel.Sync
import cats.syntax.flatMap._

import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.DeviceCode
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.UserCode
import kots.oauth2.core.Wire
import kots.oauth2.store.DeviceRecord
import kots.oauth2.store.DeviceStore

final class SqlDeviceStore[F[_]: Sync] private (connect: F[Connection], clock: Clock[F])
    extends SqlSessions[F](connect)
    with DeviceStore[F] {

  def save(record: DeviceRecord): F[Unit] = session { connection =>
    withTransaction(connection) {
      remove(connection, record.deviceCode)
      val insert = connection.prepareStatement(
        "INSERT INTO devices(device_code, user_code, client_id, scopes, expires_at, subject, " +
          "denied, last_polled_at, resource) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      try {
        insert.setString(1, record.deviceCode.value)
        insert.setString(2, record.userCode.value)
        insert.setString(3, record.clientId.value)
        insert.setString(4, Wire[Scopes].encode(record.scopes))
        insert.setTimestamp(5, Timestamp.from(record.expiresAt))
        optional(insert, 6, record.subject.map(_.value))
        insert.setBoolean(7, record.denied)
        record.lastPolledAt match {
          case Some(polled) => insert.setTimestamp(8, Timestamp.from(polled))
          case None         => insert.setNull(8, java.sql.Types.TIMESTAMP)
        }
        optional(insert, 9, record.resource.map(_.value))
        insert.executeUpdate()
        ()
      } finally insert.close()
    }
  }

  def pending(userCode: UserCode): F[Option[DeviceRecord]] =
    clock.instant.flatMap(now =>
      session { connection =>
        val select = connection.prepareStatement(
          "SELECT * FROM devices WHERE user_code = ? AND subject IS NULL AND denied = FALSE"
        )
        try {
          select.setString(1, userCode.value)
          val results = select.executeQuery()
          if (results.next()) Some(row(results)).filter(!_.isExpired(now)) else None
        } finally select.close()
      }
    )

  def approve(userCode: UserCode, subject: Subject): F[Boolean] =
    decide(userCode, "subject = ?", statement => statement.setString(1, subject.value))

  def deny(userCode: UserCode): F[Boolean] =
    decide(userCode, "denied = TRUE", _ => ())

  def poll(deviceCode: DeviceCode): F[Option[DeviceRecord]] =
    clock.instant.flatMap { now =>
      session { connection =>
        withTransaction(connection) {
          selectOne(connection, deviceCode).map { record =>
            val update = connection.prepareStatement(
              "UPDATE devices SET last_polled_at = ? WHERE device_code = ?"
            )
            try {
              update.setTimestamp(1, Timestamp.from(now))
              update.setString(2, deviceCode.value)
              update.executeUpdate()
            } finally update.close()
            record
          }
        }
      }
    }

  def consume(deviceCode: DeviceCode): F[Option[DeviceRecord]] =
    clock.instant.flatMap { now =>
      session { connection =>
        withTransaction(connection) {
          selectOne(connection, deviceCode).flatMap { record =>
            val removal = connection.prepareStatement("DELETE FROM devices WHERE device_code = ?")
            val removed =
              try {
                removal.setString(1, deviceCode.value)
                removal.executeUpdate()
              } finally removal.close()
            if (removed == 1 && !record.isExpired(now)) Some(record) else None
          }
        }
      }
    }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      session { connection =>
        val statement = connection.prepareStatement("DELETE FROM devices WHERE expires_at <= ?")
        try {
          statement.setTimestamp(1, Timestamp.from(now))
          statement.executeUpdate()
        } finally statement.close()
      }
    }

  private def decide(
      userCode: UserCode,
      assignment: String,
      bind: PreparedStatement => Unit
  ): F[Boolean] =
    clock.instant.flatMap { now =>
      session { connection =>
        val update = connection.prepareStatement(
          s"UPDATE devices SET $assignment WHERE user_code = ? " +
            "AND subject IS NULL AND denied = FALSE AND expires_at > ?"
        )
        try {
          bind(update)
          val offset = if (assignment.contains("?")) 1 else 0
          update.setString(offset + 1, userCode.value)
          update.setTimestamp(offset + 2, Timestamp.from(now))
          update.executeUpdate() == 1
        } finally update.close()
      }
    }

  private def remove(connection: Connection, deviceCode: DeviceCode): Unit = {
    val statement = connection.prepareStatement("DELETE FROM devices WHERE device_code = ?")
    try {
      statement.setString(1, deviceCode.value)
      statement.executeUpdate()
      ()
    } finally statement.close()
  }

  private def selectOne(connection: Connection, deviceCode: DeviceCode): Option[DeviceRecord] = {
    val select = connection.prepareStatement("SELECT * FROM devices WHERE device_code = ?")
    try {
      select.setString(1, deviceCode.value)
      val results = select.executeQuery()
      if (results.next()) Some(row(results)) else None
    } finally select.close()
  }

  private def row(results: ResultSet): DeviceRecord =
    DeviceRecord(
      deviceCode = DetailRows.required(DeviceCode.from(results.getString("device_code"))),
      userCode = DetailRows.required(UserCode.from(results.getString("user_code"))),
      clientId = DetailRows.required(ClientId.from(results.getString("client_id"))),
      scopes = DetailRows.required(Wire[Scopes].decode(results.getString("scopes"))),
      expiresAt = results.getTimestamp("expires_at").toInstant,
      subject = Option(results.getString("subject")).map(value => DetailRows.required(Subject.from(value))),
      denied = results.getBoolean("denied"),
      lastPolledAt = Option(results.getTimestamp("last_polled_at")).map(_.toInstant),
      resource =
        Option(results.getString("resource")).map(value => DetailRows.required(ResourceIndicator.from(value)))
    )

}

object SqlDeviceStore {

  def create[F[_]: Sync](
      connect: F[Connection],
      clock: Clock[F]
  ): Either[String, F[SqlDeviceStore[F]]] =
    Migrations
      .of(connect, Schema.migrations)
      .map(engine =>
        engine.apply.flatMap {
          case Left(reason) => Sync[F].raiseError(new IllegalStateException(reason))
          case Right(_)     => Sync[F].pure(new SqlDeviceStore(connect, clock))
        }
      )
}
