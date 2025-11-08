package dev.oauth2.core

import java.time.Instant

final case class Lifetime private (seconds: Long)

object Lifetime {
  def fromSeconds(seconds: Long): Either[ParseFailure, Lifetime] =
    Either.cond(seconds > 0L, new Lifetime(seconds), ParseFailure("Lifetime", "not positive"))

  def fromMinutes(minutes: Long): Either[ParseFailure, Lifetime] =
    fromSeconds(minutes * 60L)

  def expiresAt(issuedAt: Instant, lifetime: Lifetime): Instant =
    issuedAt.plusSeconds(lifetime.seconds)

  def isExpired(now: Instant, issuedAt: Instant, lifetime: Lifetime): Boolean =
    !now.isBefore(expiresAt(issuedAt, lifetime))
}

sealed trait TokenType

object TokenType {
  case object Access extends TokenType
  case object Refresh extends TokenType
  case object AuthorizationCode extends TokenType
}

final case class LifetimePolicy(
    accessToken: Lifetime,
    refreshToken: Lifetime,
    authorizationCode: Lifetime
)

object LifetimePolicy {
  val defaults: LifetimePolicy = LifetimePolicy(
    accessToken = Lifetime.fromSeconds(3600L).toOption.get,
    refreshToken = Lifetime.fromSeconds(2592000L).toOption.get,
    authorizationCode = Lifetime.fromSeconds(60L).toOption.get
  )

  def of(policy: LifetimePolicy, tokenType: TokenType): Lifetime = tokenType match {
    case TokenType.Access            => policy.accessToken
    case TokenType.Refresh           => policy.refreshToken
    case TokenType.AuthorizationCode => policy.authorizationCode
  }
}
