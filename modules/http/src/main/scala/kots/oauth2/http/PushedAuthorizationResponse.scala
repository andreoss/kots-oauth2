package kots.oauth2.http

import kots.oauth2.core.RequestUri

final case class PushedAuthorizationResponse(requestUri: RequestUri, expiresIn: Long)

object PushedAuthorizationResponse {

  def render(response: PushedAuthorizationResponse): Map[String, String] =
    Map(
      "request_uri" -> response.requestUri.value,
      "expires_in" -> response.expiresIn.toString
    )
}
