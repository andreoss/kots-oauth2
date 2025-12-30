package kots.oauth2.http

import kots.oauth2.core.AccessToken
import kots.oauth2.core.ExchangeTokenType
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.Scopes
import kots.oauth2.core.Wire
import io.circe.Json

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

  def render(response: TokenResponse): Map[String, Json] =
    Map(
      "access_token" -> Json.fromString(Wire[AccessToken].encode(response.accessToken)),
      "token_type" -> Json.fromString(response.tokenType),
      "expires_in" -> Json.fromLong(response.expiresIn)
    ) ++
      (if (response.scope.value.isEmpty) Map.empty[String, Json]
       else Map("scope" -> Json.fromString(Wire[Scopes].encode(response.scope)))) ++
      response.refreshToken.map(token =>
        "refresh_token" -> Json.fromString(Wire[RefreshToken].encode(token))
      ) ++
      response.issuedTokenType.map(kind => "issued_token_type" -> Json.fromString(kind.value))
}
