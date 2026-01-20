package kots.oauth2.http

import kots.oauth2.core.AccessToken
import kots.oauth2.core.ExchangeTokenType
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.Scopes
import kots.oauth2.core.Wire

final case class TokenResponse(
    accessToken: AccessToken,
    expiresIn: Long,
    scope: Scopes,
    refreshToken: Option[RefreshToken],
    issuedTokenType: Option[ExchangeTokenType] = None,
    tokenType: String = TokenResponse.TokenType
)

object TokenResponse {
  val TokenType: String = "Bearer"

  val DpopTokenType: String = "DPoP"

  def render(response: TokenResponse): Map[String, String] =
    Map(
      "access_token" -> Wire[AccessToken].encode(response.accessToken),
      "token_type" -> response.tokenType,
      "expires_in" -> response.expiresIn.toString
    ) ++
      (if (response.scope.value.isEmpty) Map.empty[String, String]
       else Map("scope" -> Wire[Scopes].encode(response.scope))) ++
      response.refreshToken.map(token => "refresh_token" -> Wire[RefreshToken].encode(token)) ++
      response.issuedTokenType.map(kind => "issued_token_type" -> kind.value)
}
