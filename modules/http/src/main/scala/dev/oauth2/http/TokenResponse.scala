package dev.oauth2.http

import dev.oauth2.core.AccessToken
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.Scopes
import dev.oauth2.core.Wire

final case class TokenResponse(
    accessToken: AccessToken,
    expiresIn: Long,
    scope: Scopes,
    refreshToken: Option[RefreshToken]
)

object TokenResponse {
  val TokenType: String = "Bearer"

  def render(response: TokenResponse): Map[String, String] =
    Map(
      "access_token" -> Wire[AccessToken].encode(response.accessToken),
      "token_type" -> TokenType,
      "expires_in" -> response.expiresIn.toString
    ) ++
      (if (response.scope.value.isEmpty) Map.empty[String, String] else Map("scope" -> Wire[Scopes].encode(response.scope))) ++
      response.refreshToken.map(token => "refresh_token" -> Wire[RefreshToken].encode(token))
}
