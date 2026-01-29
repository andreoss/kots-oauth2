package kots.oauth2.server

import cats.Monad
import cats.syntax.all._

import kots.oauth2.core.Clock
import kots.oauth2.core.DeviceAuthorizationRequest
import kots.oauth2.core.DeviceCode
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.Entropy
import kots.oauth2.core.Lifetime
import kots.oauth2.core.LifetimePolicy
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.TokenType
import kots.oauth2.core.UserCode
import kots.oauth2.http.DeviceAuthorizationResponse
import kots.oauth2.store.Client
import kots.oauth2.store.DeviceRecord
import kots.oauth2.store.DeviceStore

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
        (OAuth2Error.InvalidScope(): OAuth2Error).asLeft.pure[F]
      case requested =>
        for {
          now <- clock.instant
          rawDevice <- entropy.bytes(DeviceAuthorizationService.DeviceEntropyBytes)
          rawUser <- DeviceAuthorizationService.drawn(entropy)
          minted = (
            DeviceCode.from(Entropy.hex(rawDevice)).leftMap(DeviceAuthorizationService.failure),
            UserCode
              .from(DeviceAuthorizationService.userCode(rawUser))
              .leftMap(DeviceAuthorizationService.failure)
          ).mapN((_, _))
          result <- minted.fold(
            error => error.asLeft[DeviceAuthorizationResponse].pure[F],
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

  val UserCodeDraw: Int = 32

  val Alphabet: String = "BCDFGHJKLMNPQRSTVWXZ"

  val Interval: Lifetime = Lifetime.fromSeconds(5L).toOption.get

  val Acceptable: Int = 256 - (256 % Alphabet.length)

  def acceptable(byte: Byte): Option[Char] = {
    val value = byte & 0xff
    if (value >= Acceptable) None else Some(Alphabet(value % Alphabet.length))
  }

  def drawn[F[_]: cats.Monad](entropy: Entropy[F]): F[Array[Byte]] =
    cats.Monad[F].tailRecM(Array.empty[Byte]) { gathered =>
      entropy.bytes(UserCodeDraw).map { drawn =>
        val kept = gathered ++ drawn.filter(byte => acceptable(byte).isDefined)
        if (kept.length >= UserCodeLetters) Right(kept) else Left(kept)
      }
    }

  def userCode(raw: Array[Byte]): String = {
    val letters = raw.flatMap(acceptable).take(UserCodeLetters)
    new String(letters.take(UserCodeLetters / 2)) + "-" + new String(letters.drop(UserCodeLetters / 2))
  }

  private def failure(failure: kots.oauth2.core.ParseFailure): OAuth2Error =
    OAuth2Error.ServerError(Some(s"${failure.typeName}: ${failure.reason}"))
}
