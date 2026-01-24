package kots.oauth2.jose

import cats.syntax.all._

import kots.oauth2.core.Action
import kots.oauth2.core.AuthorizationDetail
import kots.oauth2.core.AuthorizationDetailType
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.Location
import kots.oauth2.core.ParseFailure
import io.circe.Json

object Details {

  val Claim: String = "authorization_details"

  def decode(raw: String): Either[ParseFailure, AuthorizationDetails] =
    io.circe.parser
      .parse(raw)
      .left
      .map(_ => ParseFailure("AuthorizationDetails", "not json"))
      .flatMap(of)

  def of(json: Json): Either[ParseFailure, AuthorizationDetails] =
    json.asArray
      .toRight(ParseFailure("AuthorizationDetails", "not a json array"))
      .flatMap(_.toList.traverse(one))
      .map(AuthorizationDetails.of)

  def render(details: AuthorizationDetails): Json =
    Json.fromValues(details.value.map(rendered))

  private def one(entry: Json): Either[ParseFailure, AuthorizationDetail] = {
    val cursor = entry.hcursor
    for {
      declared <- cursor
        .get[String]("type")
        .left
        .map(_ => ParseFailure("AuthorizationDetails", "no type"))
        .flatMap(AuthorizationDetailType.from)
      locations <- strings(entry, "locations").traverse(Location.from)
      actions <- strings(entry, "actions").traverse(Action.from)
    } yield AuthorizationDetail.of(declared, locations, actions, fields(entry))
  }

  private def strings(entry: Json, name: String): List[String] =
    entry.hcursor.get[List[String]](name).toOption.getOrElse(Nil)

  private def fields(entry: Json): Map[String, String] =
    entry.asObject
      .map(_.toMap.collect {
        case (name, value) if !Reserved.contains(name) && value.isString =>
          name -> value.asString.getOrElse("")
      })
      .getOrElse(Map.empty)

  private val Reserved: Set[String] = Set("type", "locations", "actions")

  private def rendered(detail: AuthorizationDetail): Json =
    Json.fromFields(
      List("type" -> Json.fromString(detail.detailType.value)) ++
        (if (detail.locations.isEmpty) Nil
         else List("locations" -> Json.fromValues(detail.locations.map(v => Json.fromString(v.value))))) ++
        (if (detail.actions.isEmpty) Nil
         else List("actions" -> Json.fromValues(detail.actions.map(v => Json.fromString(v.value))))) ++
        detail.fields.toList.sortBy(_._1).map { case (name, value) => name -> Json.fromString(value) }
    )
}
