package kots.oauth2.http

import kots.oauth2.core.DeviceCode
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.UserCode
import kots.oauth2.core.Wire
import io.circe.Json

final case class DeviceAuthorizationResponse(
    deviceCode: DeviceCode,
    userCode: UserCode,
    verificationUri: EndpointUri,
    expiresIn: Long,
    interval: Long
)

object DeviceAuthorizationResponse {

  def render(response: DeviceAuthorizationResponse): Map[String, Json] =
    Map(
      "device_code" -> Json.fromString(Wire[DeviceCode].encode(response.deviceCode)),
      "user_code" -> Json.fromString(Wire[UserCode].encode(response.userCode)),
      "verification_uri" -> Json.fromString(response.verificationUri.value),
      "expires_in" -> Json.fromLong(response.expiresIn),
      "interval" -> Json.fromLong(response.interval)
    )
}
