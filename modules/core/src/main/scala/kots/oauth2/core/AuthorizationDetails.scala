package kots.oauth2.core

import cats.Monoid

final case class AuthorizationDetailType private (value: String)

object AuthorizationDetailType {
  def from(raw: String): Either[ParseFailure, AuthorizationDetailType] =
    Text.printable("AuthorizationDetailType", raw).map(new AuthorizationDetailType(_))
}

final case class Location private (value: String)

object Location {
  def from(raw: String): Either[ParseFailure, Location] =
    Text.absolute("Location", raw).map(new Location(_))
}

final case class Action private (value: String)

object Action {
  def from(raw: String): Either[ParseFailure, Action] =
    Text.printable("Action", raw).map(new Action(_))
}

final case class AuthorizationDetail(
    detailType: AuthorizationDetailType,
    locations: List[Location],
    actions: List[Action],
    fields: Map[String, String]
)

object AuthorizationDetail {
  def of(
      detailType: AuthorizationDetailType,
      locations: List[Location] = Nil,
      actions: List[Action] = Nil,
      fields: Map[String, String] = Map.empty
  ): AuthorizationDetail =
    AuthorizationDetail(detailType, locations.distinct, actions.distinct, fields)
}

final case class AuthorizationDetails private (value: List[AuthorizationDetail])

object AuthorizationDetails {
  val empty: AuthorizationDetails = new AuthorizationDetails(Nil)

  def of(details: Iterable[AuthorizationDetail]): AuthorizationDetails =
    new AuthorizationDetails(details.toList.distinct)

  def union(a: AuthorizationDetails, b: AuthorizationDetails): AuthorizationDetails =
    of(a.value ++ b.value)

  def covers(granted: AuthorizationDetails, requested: AuthorizationDetails): Boolean =
    requested.value.forall(requested1 => granted.value.exists(granted1 => coversOne(granted1, requested1)))

  def coversOne(granted: AuthorizationDetail, requested: AuthorizationDetail): Boolean =
    granted.detailType == requested.detailType &&
      requested.locations.forall(granted.locations.contains) &&
      requested.actions.forall(granted.actions.contains) &&
      requested.fields.forall { case (k, v) => granted.fields.get(k).contains(v) }

  implicit val monoid: Monoid[AuthorizationDetails] = new Monoid[AuthorizationDetails] {
    def empty: AuthorizationDetails = AuthorizationDetails.empty

    def combine(x: AuthorizationDetails, y: AuthorizationDetails): AuthorizationDetails =
      union(x, y)
  }
}
