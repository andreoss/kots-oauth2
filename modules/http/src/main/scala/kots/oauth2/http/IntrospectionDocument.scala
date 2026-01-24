package kots.oauth2.http

import kots.oauth2.core.ClientId
import kots.oauth2.core.IntrospectionResponse
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.Wire
import io.circe.Json

object IntrospectionDocument {

  def render(response: IntrospectionResponse): Map[String, Json] =
    response match {
      case IntrospectionResponse.Inactive =>
        Map(IntrospectionResponse.ActiveFlag -> Json.False)
      case active: IntrospectionResponse.Active =>
        Map(
          IntrospectionResponse.ActiveFlag -> Json.True,
          "client_id" -> Json.fromString(Wire[ClientId].encode(active.clientId)),
          "username" -> Json.fromString(Wire[Subject].encode(active.username)),
          "token_type" -> Json.fromString(IntrospectionResponse.Active.tokenType(active.kind)),
          "exp" -> Json.fromLong(active.expiresAt.getEpochSecond),
          "iat" -> Json.fromLong(active.issuedAt.getEpochSecond),
          "nbf" -> Json.fromLong(active.notBefore.getEpochSecond),
          "sub" -> Json.fromString(Wire[Subject].encode(active.username))
        ) ++ (if (active.scopes.value.isEmpty) Map.empty[String, Json]
              else Map("scope" -> Json.fromString(Wire[Scopes].encode(active.scopes))))
    }
}
