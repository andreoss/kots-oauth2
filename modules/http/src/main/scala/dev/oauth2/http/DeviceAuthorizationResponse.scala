package dev.oauth2.http

import dev.oauth2.core.DeviceCode
import dev.oauth2.core.EndpointUri
import dev.oauth2.core.UserCode
import dev.oauth2.core.Wire

final case class DeviceAuthorizationResponse(
    deviceCode: DeviceCode,
    userCode: UserCode,
    verificationUri: EndpointUri,
    expiresIn: Long,
    interval: Long
)

object DeviceAuthorizationResponse {

  def render(response: DeviceAuthorizationResponse): Map[String, String] =
    Map(
      "device_code" -> Wire[DeviceCode].encode(response.deviceCode),
      "user_code" -> Wire[UserCode].encode(response.userCode),
      "verification_uri" -> response.verificationUri.value,
      "expires_in" -> response.expiresIn.toString,
      "interval" -> response.interval.toString
    )
}
