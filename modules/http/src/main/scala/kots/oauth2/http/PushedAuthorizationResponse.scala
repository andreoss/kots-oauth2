package kots.oauth2.http

import kots.oauth2.core.RequestUri
import io.circe.Json

final case class PushedAuthorizationResponse(requestUri: RequestUri, expiresIn: Long)

object PushedAuthorizationResponse {

  def render(response: PushedAuthorizationResponse): Map[String, Json] =
    Map(
      "request_uri" -> Json.fromString(response.requestUri.value),
      "expires_in" -> Json.fromLong(response.expiresIn)
    )
}
