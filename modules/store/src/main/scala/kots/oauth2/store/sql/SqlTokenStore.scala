package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp

import cats.effect.kernel.Sync
import cats.syntax.flatMap._

import kots.oauth2.core.AccessToken
import kots.oauth2.core.AccessTokenHash
import kots.oauth2.core.Audience
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.GrantType
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.RefreshTokenHash
import kots.oauth2.core.RevocationToken
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.TokenTypeHint
import kots.oauth2.core.Wire
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.TokenStore

final class SqlTokenStore[F[_]: Sync] private (connect: F[Connection], clock: Clock[F])
    extends SqlSessions[F](connect)
    with TokenStore[F] {

  def save(record: TokenRecord): F[Unit] = session { connection =>
    withTransaction(connection) {
      update(connection, "DELETE FROM token_details WHERE access_hash = ?", record.accessTokenHash.value)
      update(connection, "DELETE FROM tokens WHERE access_hash = ?", record.accessTokenHash.value)
      insertRecord(connection, record)
    }
  }

  def findByAccess(token: AccessToken): F[Option[TokenRecord]] =
    clock.instant.flatMap { now =>
      session { connection =>
        selectOne(connection, "SELECT * FROM tokens WHERE access_hash = ?", AccessTokenHash.of(token).value)
          .flatMap { record =>
            if (!record.isAccessExpired(now) && record.matchesAccess(token)) Some(record)
            else {
              purge(connection, record.accessTokenHash)
              None
            }
          }
      }
    }

  def findByRefresh(token: RefreshToken): F[Option[TokenRecord]] =
    clock.instant.flatMap { now =>
      session { connection =>
        RefreshTokenHash.of(token) match {
          case hash =>
            selectOne(connection, "SELECT * FROM tokens WHERE refresh_hash = ?", hash.value).flatMap {
              record =>
                if (!record.isRefreshExpired(now) && record.matchesRefresh(token)) Some(record)
                else {
                  purge(connection, record.accessTokenHash)
                  None
                }
            }
        }
      }
    }

  def drop(refreshToken: RefreshToken): F[Unit] = session { connection =>
    dropByRefresh(connection, refreshToken)
  }

  def retire(refreshToken: RefreshToken, grantId: GrantId): F[Unit] = session { connection =>
    withTransaction(connection) {
      dropByRefresh(connection, refreshToken)
      val hash = RefreshTokenHash.of(refreshToken).value
      update(connection, "DELETE FROM retired_tokens WHERE refresh_hash = ?", hash)
      val insert = connection.prepareStatement(
        "INSERT INTO retired_tokens(refresh_hash, grant_id) VALUES(?, ?)"
      )
      try {
        insert.setString(1, hash)
        insert.setString(2, grantId.value)
        insert.executeUpdate()
        ()
      } finally insert.close()
    }
  }

  def rotated(refreshToken: RefreshToken): F[Option[GrantId]] = session { connection =>
    val select = connection.prepareStatement(
      "SELECT grant_id FROM retired_tokens WHERE refresh_hash = ?"
    )
    try {
      select.setString(1, RefreshTokenHash.of(refreshToken).value)
      val results = select.executeQuery()
      if (results.next()) Some(required(GrantId.from(results.getString(1)))) else None
    } finally select.close()
  }

  def revoke(
      token: RevocationToken,
      hint: Option[TokenTypeHint],
      clientId: ClientId
  ): F[Option[GrantId]] = session { connection =>
    def byRefresh: Option[Option[GrantId]] =
      RevocationToken.asRefreshToken(token).flatMap { refresh =>
        selectOne(
          connection,
          "SELECT * FROM tokens WHERE refresh_hash = ? AND client_id = ?",
          RefreshTokenHash.of(refresh).value,
          clientId.value
        ).map { record =>
          revokeGrantRows(connection, record.grantId)
          Some(record.grantId)
        }
      }
    def byAccess: Option[Option[GrantId]] =
      RevocationToken.asAccessToken(token).flatMap { access =>
        selectOne(
          connection,
          "SELECT * FROM tokens WHERE access_hash = ? AND client_id = ?",
          AccessTokenHash.of(access).value,
          clientId.value
        ).map { record =>
          purge(connection, record.accessTokenHash)
          None
        }
      }
    val outcome = hint match {
      case Some(TokenTypeHint.RefreshToken) => byRefresh
      case Some(TokenTypeHint.AccessToken)  => byAccess
      case None                             => byRefresh.orElse(byAccess)
    }
    outcome.flatten
  }

  def revokeGrant(grantId: GrantId): F[Unit] = session { connection =>
    revokeGrantRows(connection, grantId)
  }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      session { connection =>
        val moment = Timestamp.from(now)
        val details = connection.prepareStatement(
          "DELETE FROM token_details WHERE access_hash IN (SELECT access_hash FROM tokens " +
            "WHERE access_expires_at <= ? AND (refresh_expires_at IS NULL OR refresh_expires_at <= ?))"
        )
        try {
          details.setTimestamp(1, moment)
          details.setTimestamp(2, moment)
          details.executeUpdate()
        } finally details.close()
        val tokens = connection.prepareStatement(
          "DELETE FROM tokens WHERE access_expires_at <= ? " +
            "AND (refresh_expires_at IS NULL OR refresh_expires_at <= ?)"
        )
        try {
          tokens.setTimestamp(1, moment)
          tokens.setTimestamp(2, moment)
          tokens.executeUpdate()
        } finally tokens.close()
      }
    }

  private def dropByRefresh(connection: Connection, refreshToken: RefreshToken): Unit = {
    val hash = RefreshTokenHash.of(refreshToken).value
    update(
      connection,
      "DELETE FROM token_details WHERE access_hash IN (SELECT access_hash FROM tokens " +
        "WHERE refresh_hash = ?)",
      hash
    )
    update(connection, "DELETE FROM tokens WHERE refresh_hash = ?", hash)
  }

  private def revokeGrantRows(connection: Connection, grantId: GrantId): Unit = {
    update(
      connection,
      "DELETE FROM token_details WHERE access_hash IN (SELECT access_hash FROM tokens " +
        "WHERE grant_id = ?)",
      grantId.value
    )
    update(connection, "DELETE FROM tokens WHERE grant_id = ?", grantId.value)
  }

  private def purge(connection: Connection, hash: AccessTokenHash): Unit = {
    update(connection, "DELETE FROM token_details WHERE access_hash = ?", hash.value)
    update(connection, "DELETE FROM tokens WHERE access_hash = ?", hash.value)
  }

  private def insertRecord(connection: Connection, record: TokenRecord): Unit = {
    val insert = connection.prepareStatement(
      "INSERT INTO tokens(access_hash, refresh_hash, grant_id, client_id, subject, scopes, " +
        "issued_at, access_expires_at, refresh_expires_at, audience, actor, grant_type) " +
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    try {
      insert.setString(1, record.accessTokenHash.value)
      optional(insert, 2, record.refreshTokenHash.map(_.value))
      insert.setString(3, record.grantId.value)
      insert.setString(4, record.clientId.value)
      insert.setString(5, record.subject.value)
      insert.setString(6, Wire[Scopes].encode(record.scopes))
      insert.setTimestamp(7, Timestamp.from(record.issuedAt))
      insert.setTimestamp(8, Timestamp.from(record.accessExpiresAt))
      record.refreshExpiresAt match {
        case Some(expiry) => insert.setTimestamp(9, Timestamp.from(expiry))
        case None         => insert.setNull(9, java.sql.Types.TIMESTAMP)
      }
      optional(insert, 10, record.audience.map(_.value))
      optional(insert, 11, record.actor.map(_.value))
      insert.setString(12, record.grant.value)
      insert.executeUpdate()
      ()
    } finally insert.close()
    DetailRows.insert(
      connection,
      "token_details",
      "access_hash",
      record.accessTokenHash.value,
      record.details
    )
  }

  private def selectOne(connection: Connection, sql: String, values: String*): Option[TokenRecord] = {
    val select = connection.prepareStatement(sql)
    try {
      values.zipWithIndex.foreach { case (value, index) => select.setString(index + 1, value) }
      val results = select.executeQuery()
      if (results.next()) Some(row(connection, results)) else None
    } finally select.close()
  }

  private def row(connection: Connection, results: ResultSet): TokenRecord =
    TokenRecord(
      accessTokenHash = required(AccessTokenHash.fromStored(results.getString("access_hash"))),
      refreshTokenHash =
        Option(results.getString("refresh_hash")).map(raw => required(RefreshTokenHash.fromStored(raw))),
      grantId = required(GrantId.from(results.getString("grant_id"))),
      clientId = required(ClientId.from(results.getString("client_id"))),
      subject = required(Subject.from(results.getString("subject"))),
      scopes = required(Wire[Scopes].decode(results.getString("scopes"))),
      details = detailsOf(connection, results.getString("access_hash")),
      issuedAt = results.getTimestamp("issued_at").toInstant,
      accessExpiresAt = results.getTimestamp("access_expires_at").toInstant,
      refreshExpiresAt = Option(results.getTimestamp("refresh_expires_at")).map(_.toInstant),
      audience = Option(results.getString("audience")).map(value => required(Audience.from(value))),
      actor = Option(results.getString("actor")).map(value => required(Subject.from(value))),
      grant = Option(results.getString("grant_type"))
        .flatMap(raw => GrantType.from(raw).toOption)
        .getOrElse(GrantType.AuthorizationCode)
    )

  private def detailsOf(connection: Connection, accessHash: String): AuthorizationDetails =
    DetailRows.read(connection, "token_details", "access_hash", accessHash)

  private def required[A](parsed: Either[ParseFailure, A]): A = DetailRows.required(parsed)

}

object SqlTokenStore {

  def create[F[_]: Sync](
      connect: F[Connection],
      clock: Clock[F]
  ): Either[String, F[SqlTokenStore[F]]] =
    Migrations
      .of(connect, Schema.migrations)
      .map(engine =>
        engine.apply.flatMap {
          case Left(reason) => Sync[F].raiseError(new IllegalStateException(reason))
          case Right(_)     => Sync[F].pure(new SqlTokenStore(connect, clock))
        }
      )
}
