package kots.oauth2.store.sql

import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Timestamp

import cats.effect.kernel.Resource
import cats.effect.kernel.Sync
import cats.syntax.flatMap._

import kots.oauth2.core.AccessToken
import kots.oauth2.core.AccessTokenHash
import kots.oauth2.core.Action
import kots.oauth2.core.Audience
import kots.oauth2.core.AuthorizationDetail
import kots.oauth2.core.AuthorizationDetailType
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.Location
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
    extends TokenStore[F] {

  def save(record: TokenRecord): F[Unit] = session { connection =>
    withTransaction(connection) {
      delete(connection, "DELETE FROM token_details WHERE access_hash = ?", record.accessTokenHash.value)
      delete(connection, "DELETE FROM tokens WHERE access_hash = ?", record.accessTokenHash.value)
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
      delete(connection, "DELETE FROM retired_tokens WHERE refresh_hash = ?", hash)
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
    delete(
      connection,
      "DELETE FROM token_details WHERE access_hash IN (SELECT access_hash FROM tokens " +
        "WHERE refresh_hash = ?)",
      hash
    )
    delete(connection, "DELETE FROM tokens WHERE refresh_hash = ?", hash)
  }

  private def revokeGrantRows(connection: Connection, grantId: GrantId): Unit = {
    delete(
      connection,
      "DELETE FROM token_details WHERE access_hash IN (SELECT access_hash FROM tokens " +
        "WHERE grant_id = ?)",
      grantId.value
    )
    delete(connection, "DELETE FROM tokens WHERE grant_id = ?", grantId.value)
  }

  private def purge(connection: Connection, hash: AccessTokenHash): Unit = {
    delete(connection, "DELETE FROM token_details WHERE access_hash = ?", hash.value)
    delete(connection, "DELETE FROM tokens WHERE access_hash = ?", hash.value)
  }

  private def delete(connection: Connection, sql: String, values: String*): Unit = {
    val statement = connection.prepareStatement(sql)
    try {
      values.zipWithIndex.foreach { case (value, index) => statement.setString(index + 1, value) }
      statement.executeUpdate()
      ()
    } finally statement.close()
  }

  private def insertRecord(connection: Connection, record: TokenRecord): Unit = {
    val insert = connection.prepareStatement(
      "INSERT INTO tokens(access_hash, refresh_hash, grant_id, client_id, subject, scopes, " +
        "issued_at, access_expires_at, refresh_expires_at, audience, actor) " +
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
      insert.executeUpdate()
      ()
    } finally insert.close()
    record.details.value.zipWithIndex.foreach { case (detail, index) =>
      val child = connection.prepareStatement(
        "INSERT INTO token_details(access_hash, ord, detail_type, locations, actions, fields) " +
          "VALUES(?, ?, ?, ?, ?, ?)"
      )
      try {
        child.setString(1, record.accessTokenHash.value)
        child.setInt(2, index)
        child.setString(3, detail.detailType.value)
        child.setString(4, detail.locations.map(_.value).mkString(" "))
        child.setString(5, detail.actions.map(_.value).mkString(" "))
        child.setString(6, encodeFields(detail.fields))
        child.executeUpdate()
        ()
      } finally child.close()
    }
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
      actor = Option(results.getString("actor")).map(value => required(Subject.from(value)))
    )

  private def detailsOf(connection: Connection, accessHash: String): AuthorizationDetails = {
    val select = connection.prepareStatement(
      "SELECT detail_type, locations, actions, fields FROM token_details " +
        "WHERE access_hash = ? ORDER BY ord"
    )
    try {
      select.setString(1, accessHash)
      val results = select.executeQuery()
      val details = Iterator
        .continually(results)
        .takeWhile(_.next())
        .map(row =>
          AuthorizationDetail.of(
            required(AuthorizationDetailType.from(row.getString(1))),
            split(row.getString(2)).map(value => required(Location.from(value))),
            split(row.getString(3)).map(value => required(Action.from(value))),
            decodeFields(row.getString(4))
          )
        )
        .toList
      AuthorizationDetails.of(details)
    } finally select.close()
  }

  private def split(joined: String): List[String] =
    joined.split(' ').toList.filter(_.nonEmpty)

  private def encodeFields(fields: Map[String, String]): String =
    fields.toList.sorted
      .map { case (name, value) =>
        URLEncoder.encode(name, StandardCharsets.UTF_8.name) + "=" +
          URLEncoder.encode(value, StandardCharsets.UTF_8.name)
      }
      .mkString("&")

  private def decodeFields(joined: String): Map[String, String] =
    joined
      .split('&')
      .toList
      .filter(_.nonEmpty)
      .map { pair =>
        pair.split('=') match {
          case Array(name, value) =>
            URLDecoder.decode(name, StandardCharsets.UTF_8.name) ->
              URLDecoder.decode(value, StandardCharsets.UTF_8.name)
          case _ => URLDecoder.decode(pair, StandardCharsets.UTF_8.name) -> ""
        }
      }
      .toMap

  private def optional(statement: PreparedStatement, index: Int, value: Option[String]): Unit =
    value match {
      case Some(present) => statement.setString(index, present)
      case None          => statement.setNull(index, java.sql.Types.VARCHAR)
    }

  private def required[A](parsed: Either[ParseFailure, A]): A =
    parsed.left.map(failure => new IllegalStateException(failure.toString): Throwable).toTry.get

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

object SqlTokenStore {

  val migrations: List[Migration] = List(
    Migration(
      1,
      "CREATE TABLE tokens(" +
        "access_hash VARCHAR(64) PRIMARY KEY, refresh_hash VARCHAR(64), " +
        "grant_id VARCHAR(512) NOT NULL, client_id VARCHAR(512) NOT NULL, " +
        "subject VARCHAR(512) NOT NULL, scopes VARCHAR(2048) NOT NULL, " +
        "issued_at TIMESTAMP NOT NULL, access_expires_at TIMESTAMP NOT NULL, " +
        "refresh_expires_at TIMESTAMP, audience VARCHAR(512), actor VARCHAR(512));" +
        "CREATE INDEX tokens_refresh ON tokens(refresh_hash);" +
        "CREATE INDEX tokens_grant ON tokens(grant_id);" +
        "CREATE TABLE token_details(" +
        "access_hash VARCHAR(64) NOT NULL, ord INT NOT NULL, detail_type VARCHAR(512) NOT NULL, " +
        "locations VARCHAR(2048) NOT NULL, actions VARCHAR(2048) NOT NULL, " +
        "fields VARCHAR(4096) NOT NULL, PRIMARY KEY(access_hash, ord));" +
        "CREATE TABLE retired_tokens(" +
        "refresh_hash VARCHAR(64) PRIMARY KEY, grant_id VARCHAR(512) NOT NULL)"
    )
  )

  def create[F[_]: Sync](
      connect: F[Connection],
      clock: Clock[F]
  ): Either[String, F[SqlTokenStore[F]]] =
    Migrations
      .of(connect, migrations)
      .map(engine =>
        engine.apply.flatMap {
          case Left(reason) => Sync[F].raiseError(new IllegalStateException(reason))
          case Right(_)     => Sync[F].pure(new SqlTokenStore(connect, clock))
        }
      )
}
