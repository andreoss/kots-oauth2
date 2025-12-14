package dev.oauth2.http

import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientRegistration
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.RegistrationToken
import dev.oauth2.core.Wire
import io.circe.Json

final case class ClientRegistrationResponse(
    clientId: ClientId,
    secret: Option[ClientSecret],
    registration: ClientRegistration,
    registrationToken: Option[RegistrationToken] = None
)

object ClientRegistrationResponse {

  def render(response: ClientRegistrationResponse): Map[String, Json] =
    Map(
      "client_id" -> Json.fromString(Wire[ClientId].encode(response.clientId)),
      Registration.TokenEndpointAuthMethod -> Json.fromString(response.registration.authMethod.value),
      Registration.RedirectUris -> Json.arr(
        response.registration.redirectUris
          .map(uri => Json.fromString(uri.value))
          .toVector
          .sortBy(_.asString): _*
      ),
      Registration.Scope -> Json.fromString(
        response.registration.scopes.value.map(_.value).toVector.sorted.mkString(" ")
      )
    ) ++ response.secret.map(secret => "client_secret" -> Json.fromString(secret.value)) ++
      response.registrationToken.map(token => "registration_access_token" -> Json.fromString(token.value))
}
