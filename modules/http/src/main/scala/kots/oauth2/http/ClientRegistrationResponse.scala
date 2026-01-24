package kots.oauth2.http

import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientRegistration
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.RegistrationToken
import kots.oauth2.core.Wire
import io.circe.Json

final case class ClientRegistrationResponse(
    clientId: ClientId,
    secret: Option[ClientSecret],
    registration: ClientRegistration,
    registrationToken: Option[RegistrationToken] = None,
    secretExpiresAt: Long = ClientRegistrationResponse.NeverExpires
)

object ClientRegistrationResponse {

  val NeverExpires: Long = 0L

  def render(response: ClientRegistrationResponse): Map[String, Json] =
    Map(
      "client_id" -> Json.fromString(Wire[ClientId].encode(response.clientId)),
      Registration.TokenEndpointAuthMethod -> Json.fromString(response.registration.authMethod.value),
      Registration.RedirectUris -> Json.arr(
        response.registration.redirectUris
          .map(uri => Json.fromString(uri.value))
          .toVector
          .sortBy(_.asString): _*
      )
    ) ++
      (if (response.registration.scopes.value.isEmpty) Map.empty[String, Json]
       else
         Map(
           Registration.Scope -> Json.fromString(
             response.registration.scopes.value.map(_.value).toVector.sorted.mkString(" ")
           )
         )) ++
      response.secret.toList.flatMap(secret =>
        List(
          "client_secret" -> Json.fromString(secret.value),
          Registration.SecretExpiresAt -> Json.fromLong(response.secretExpiresAt)
        )
      ) ++
      response.registrationToken.map(token => "registration_access_token" -> Json.fromString(token.value))
}
