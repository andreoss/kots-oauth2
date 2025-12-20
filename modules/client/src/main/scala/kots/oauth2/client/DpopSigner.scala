package kots.oauth2.client

import java.security.PrivateKey

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.Clock
import kots.oauth2.core.Entropy
import kots.oauth2.core.JwtId
import kots.oauth2.core.ParseFailure
import kots.oauth2.jose.Alg
import kots.oauth2.jose.Dpop
import kots.oauth2.jose.Jwk

final class DpopSigner[F[_]: Monad] private (
    entropy: Entropy[F],
    clock: Clock[F],
    alg: Alg,
    key: PrivateKey,
    jwk: Jwk,
    nonces: Ref[F, Option[String]]
) {

  def proof(method: String, uri: String): F[Either[ParseFailure, String]] =
    for {
      raw <- entropy.bytes(DpopSigner.JtiEntropyBytes)
      now <- clock.instant
      nonce <- nonces.get
    } yield JwtId
      .from(Entropy.hex(raw))
      .flatMap(jti => Dpop.prove(alg, key, jwk, jti, method, uri, now, nonce))

  def learn(nonce: Option[String]): F[Unit] =
    nonce.fold(Monad[F].unit)(value => nonces.set(Some(value)))
}

object DpopSigner {

  val JtiEntropyBytes: Int = 16

  def create[F[_]: cats.effect.Sync](
      entropy: Entropy[F],
      clock: Clock[F],
      alg: Alg,
      key: PrivateKey,
      jwk: Jwk
  ): F[DpopSigner[F]] =
    Ref
      .of[F, Option[String]](None)
      .map(nonces => new DpopSigner(entropy, clock, alg, key, jwk, nonces))
}
