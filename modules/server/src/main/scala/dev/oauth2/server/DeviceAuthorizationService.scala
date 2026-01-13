package dev.oauth2.server

import cats.Monad
import cats.syntax.all._

import dev.oauth2.core.Clock
import dev.oauth2.core.DeviceAuthorizationRequest
import dev.oauth2.core.DeviceCode
import dev.oauth2.core.EndpointUri
import dev.oauth2.core.Entropy
import dev.oauth2.core.Lifetime
import dev.oauth2.core.LifetimePolicy
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.TokenType
import dev.oauth2.core.UserCode
import dev.oauth2.http.DeviceAuthorizationResponse
import dev.oauth2.store.Client
import dev.oauth2.store.DeviceRecord
import dev.oauth2.store.DeviceStore

final class DeviceAuthorizationService[F[_]: Monad](
    devices: DeviceStore[F],
    clock: Clock[F],
    entropy: Entropy[F],
    policy: LifetimePolicy,
    verificationUri: EndpointUri
) {

  def authorize(
      request: DeviceAuthorizationRequest,
      client: Client
  ): F[Either[OAuth2Error, DeviceAuthorizationResponse]] =
    request.scope match {
      case Some(scopes) if !client.allowsScopes(scopes) =>
        Monad[F].pure(Left(OAuth2Error.InvalidScope(): OAuth2Error))
      case requested =>
        for {
          now <- clock.instant
          rawDevice <- entropy.bytes(DeviceAuthorizationService.DeviceEntropyBytes)
          rawUser <- entropy.bytes(DeviceAuthorizationService.UserCodeLetters)
          minted = (
            DeviceCode.from(Entropy.hex(rawDevice)).leftMap(DeviceAuthorizationService.failure),
            UserCode.from(DeviceAuthorizationService.userCode(rawUser)).leftMap(DeviceAuthorizationService.failure)
          ).mapN((_, _))
          result <- minted.fold(
            error => Monad[F].pure(Left(error): Either[OAuth2Error, DeviceAuthorizationResponse]),
            { case (deviceCode, userCode) =>
              val lifetime = LifetimePolicy.of(policy, TokenType.DeviceCode)
              devices
                .save(
                  DeviceRecord(
                    deviceCode = deviceCode,
                    userCode = userCode,
                    clientId = client.id,
                    scopes = requested.getOrElse(client.scopes),
                    expiresAt = Lifetime.expiresAt(now, lifetime),
                    subject = None,
                    denied = false,
                    lastPolledAt = None,
                    resource = request.resource
                  )
                )
                .as(
                  Right(
                    DeviceAuthorizationResponse(
                      deviceCode = deviceCode,
                      userCode = userCode,
                      verificationUri = verificationUri,
                      expiresIn = lifetime.seconds,
                      interval = DeviceAuthorizationService.Interval.seconds
                    )
                  ): Either[OAuth2Error, DeviceAuthorizationResponse]
                )
            }
          )
        } yield result
    }
}

object DeviceAuthorizationService {

  val DeviceEntropyBytes: Int = 32

  val UserCodeLetters: Int = 8

  val Alphabet: String = "BCDFGHJKLMNPQRSTVWXZ"

  val Interval: Lifetime = Lifetime.fromSeconds(5L).toOption.get

  def userCode(raw: Array[Byte]): String = {
    val letters = raw.take(UserCodeLetters).map(b => Alphabet((b & 0x7f) % Alphabet.length))
    new String(letters.take(UserCodeLetters / 2)) + "-" + new String(letters.drop(UserCodeLetters / 2))
  }

  private def failure(failure: dev.oauth2.core.ParseFailure): OAuth2Error =
    OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
}
