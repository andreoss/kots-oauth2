package kots.oauth2.store.sql

import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.sql.Connection

import kots.oauth2.core.Action
import kots.oauth2.core.AuthorizationDetail
import kots.oauth2.core.AuthorizationDetailType
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.Location
import kots.oauth2.core.ParseFailure

private[sql] object DetailRows {

  def insert(
      connection: Connection,
      table: String,
      keyColumn: String,
      key: String,
      details: AuthorizationDetails
  ): Unit =
    details.value.zipWithIndex.foreach { case (detail, index) =>
      val child = connection.prepareStatement(
        s"INSERT INTO $table($keyColumn, ord, detail_type, locations, actions, fields) " +
          "VALUES(?, ?, ?, ?, ?, ?)"
      )
      try {
        child.setString(1, key)
        child.setInt(2, index)
        child.setString(3, detail.detailType.value)
        child.setString(4, detail.locations.map(_.value).mkString(" "))
        child.setString(5, detail.actions.map(_.value).mkString(" "))
        child.setString(6, encodeFields(detail.fields))
        child.executeUpdate()
        ()
      } finally child.close()
    }

  def read(connection: Connection, table: String, keyColumn: String, key: String): AuthorizationDetails = {
    val select = connection.prepareStatement(
      s"SELECT detail_type, locations, actions, fields FROM $table WHERE $keyColumn = ? ORDER BY ord"
    )
    try {
      select.setString(1, key)
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

  def required[A](parsed: Either[ParseFailure, A]): A =
    parsed.left.map(failure => new IllegalStateException(failure.toString): Throwable).toTry.get

  private def split(joined: String): List[String] =
    joined.split(' ').toList.filter(_.nonEmpty)

  private[sql] def encodeFields(fields: Map[String, String]): String =
    fields.toList.sorted
      .map { case (name, value) =>
        URLEncoder.encode(name, StandardCharsets.UTF_8.name) + "=" +
          URLEncoder.encode(value, StandardCharsets.UTF_8.name)
      }
      .mkString("&")

  private[sql] def decodeFields(joined: String): Map[String, String] =
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
}
