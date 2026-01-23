package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet

import cats.effect.kernel.Resource
import cats.effect.kernel.Sync
import cats.syntax.flatMap._

import kots.oauth2.core.CertificateSubject
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.RegistrationTokenHash
import kots.oauth2.core.Scopes
import kots.oauth2.core.Wire
import kots.oauth2.jose.Jwks
import kots.oauth2.store.Client
import kots.oauth2.store.ClientStore

final class SqlClientStore[F[_]: Sync] private (connect: F[Connection]) extends ClientStore[F] {

  def find(id: ClientId): F[Option[Client]] = session { connection =>
    val select = connection.prepareStatement("SELECT * FROM clients WHERE client_id = ?")
    try {
      select.setString(1, id.value)
      val results = select.executeQuery()
      if (results.next()) Some(row(connection, results)) else None
    } finally select.close()
  }

  def save(client: Client): F[Unit] = session { connection =>
    withTransaction(connection) {
      remove(connection, client.id)
      val insert = connection.prepareStatement(
        "INSERT INTO clients(client_id, redirect_uris, scopes, auth_method, secret_hash, " +
          "registration_token_hash, secret, certificate_subject, certificate_thumbprint) " +
          "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      try {
        insert.setString(1, client.id.value)
        insert.setString(2, client.redirectUris.map(_.value).toList.sorted.mkString(" "))
        insert.setString(3, Wire[Scopes].encode(client.scopes))
        insert.setString(4, client.authMethod.value)
        optional(insert, 5, client.secretHash.map(_.value))
        optional(insert, 6, client.registrationTokenHash.map(_.value))
        optional(insert, 7, client.secret.map(_.value))
        optional(insert, 8, client.certificateSubject.map(_.value))
        optional(insert, 9, client.certificateThumbprint.map(_.value))
        insert.executeUpdate()
        ()
      } finally insert.close()
      client.keys.keys.zipWithIndex.foreach { case (key, index) =>
        val child = connection.prepareStatement(
          "INSERT INTO client_keys(client_id, ord, kid, alg, params) VALUES(?, ?, ?, ?, ?)"
        )
        try {
          child.setString(1, client.id.value)
          child.setInt(2, index)
          child.setString(3, key.kid.value)
          child.setString(4, key.alg.value)
          child.setString(5, KeyRows.encode(key))
          child.executeUpdate()
          ()
        } finally child.close()
      }
    }
  }

  def delete(id: ClientId): F[Unit] = session { connection =>
    withTransaction(connection)(remove(connection, id))
  }

  private def remove(connection: Connection, id: ClientId): Unit = {
    val keys = connection.prepareStatement("DELETE FROM client_keys WHERE client_id = ?")
    try {
      keys.setString(1, id.value)
      keys.executeUpdate()
      ()
    } finally keys.close()
    val clients = connection.prepareStatement("DELETE FROM clients WHERE client_id = ?")
    try {
      clients.setString(1, id.value)
      clients.executeUpdate()
      ()
    } finally clients.close()
  }

  private def row(connection: Connection, results: ResultSet): Client =
    Client(
      id = DetailRows.required(ClientId.from(results.getString("client_id"))),
      redirectUris = results
        .getString("redirect_uris")
        .split(' ')
        .toList
        .filter(_.nonEmpty)
        .map(value => DetailRows.required(RedirectUri.from(value)))
        .toSet,
      scopes = DetailRows.required(Wire[Scopes].decode(results.getString("scopes"))),
      authMethod = DetailRows.required(ClientAuthMethod.from(results.getString("auth_method"))),
      secretHash = Option(results.getString("secret_hash")).map(raw =>
        DetailRows.required(ClientSecretHash.fromStored(raw))
      ),
      keys = keysOf(connection, results.getString("client_id")),
      registrationTokenHash = Option(results.getString("registration_token_hash")).map(raw =>
        DetailRows.required(RegistrationTokenHash.fromStored(raw))
      ),
      secret = Option(results.getString("secret")).map(raw => DetailRows.required(ClientSecret.from(raw))),
      certificateSubject = Option(results.getString("certificate_subject")).map(raw =>
        DetailRows.required(CertificateSubject.from(raw))
      ),
      certificateThumbprint = Option(results.getString("certificate_thumbprint")).map(raw =>
        DetailRows.required(CertificateThumbprint.from(raw))
      )
    )

  private def keysOf(connection: Connection, clientId: String): Jwks = {
    val select = connection.prepareStatement(
      "SELECT kid, alg, params FROM client_keys WHERE client_id = ? ORDER BY ord"
    )
    try {
      select.setString(1, clientId)
      val results = select.executeQuery()
      val keys = Iterator
        .continually(results)
        .takeWhile(_.next())
        .map(entry => KeyRows.keyOf(entry.getString(1), entry.getString(2), entry.getString(3)))
        .toList
      Jwks(keys)
    } finally select.close()
  }

  private def optional(statement: PreparedStatement, index: Int, value: Option[String]): Unit =
    value match {
      case Some(present) => statement.setString(index, present)
      case None          => statement.setNull(index, java.sql.Types.VARCHAR)
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

object SqlClientStore {

  def create[F[_]: Sync](connect: F[Connection]): Either[String, F[SqlClientStore[F]]] =
    Migrations
      .of(connect, Schema.migrations)
      .map(engine =>
        engine.apply.flatMap {
          case Left(reason) => Sync[F].raiseError(new IllegalStateException(reason))
          case Right(_)     => Sync[F].pure(new SqlClientStore(connect))
        }
      )
}
