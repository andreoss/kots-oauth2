package dev.oauth2.server

import java.time.Instant

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.Clock
import dev.oauth2.core.KeyThumbprint
import dev.oauth2.core.OAuth2Error
import dev.oauth2.jose.Dpop
import dev.oauth2.store.ReplayStore

final class DpopProofs[F[_]: Monad](
    replays: ReplayStore[F],
    clock: Clock[F],
    nonce: Option[F[String]] = None
) {

  def validate(compact: String, method: String, uri: String): F[Either[OAuth2Error, KeyThumbprint]] =
    clock.instant.flatMap { now =>
      Dpop.verify(compact) match {
        case Left(failure) =>
          Monad[F].pure(Left(DpopProofs.invalid(failure.reason)): Either[OAuth2Error, KeyThumbprint])
        case Right(proof) =>
          checked(proof, method, uri, now) match {
            case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, KeyThumbprint])
            case Right(())   =>
              demanded(proof.nonce).flatMap {
                case Left(error) => Monad[F].pure(Left(error): Either[OAuth2Error, KeyThumbprint])
                case Right(())   =>
                  replays.record(proof.jti, proof.issuedAt.plusSeconds(DpopProofs.WindowSeconds)).map {
                    case true  => Right(proof.thumbprint): Either[OAuth2Error, KeyThumbprint]
                    case false => Left(DpopProofs.invalid("the proof was already seen"))
                  }
              }
          }
      }
    }

  private def checked(
      proof: Dpop.Proof,
      method: String,
      uri: String,
      now: Instant
  ): Either[OAuth2Error, Unit] =
    for {
      _ <- refuse(proof.method == method, "the proof is for another method")
      _ <- refuse(proof.uri == uri, "the proof is for another uri")
      _ <- refuse(
        !proof.issuedAt.isBefore(now.minusSeconds(DpopProofs.WindowSeconds)) &&
          !proof.issuedAt.isAfter(now.plusSeconds(DpopProofs.WindowSeconds)),
        "the proof is outside the freshness window"
      )
    } yield ()

  private def demanded(carried: Option[String]): F[Either[OAuth2Error, Unit]] =
    nonce match {
      case None          => Monad[F].pure(Right(()): Either[OAuth2Error, Unit])
      case Some(current) =>
        current.map(expected =>
          Either.cond(carried.contains(expected), (), OAuth2Error.UseDpopNonce(): OAuth2Error)
        )
    }

  private def refuse(holds: Boolean, reason: String): Either[OAuth2Error, Unit] =
    Either.cond(holds, (), DpopProofs.invalid(reason))
}

object DpopProofs {

  val WindowSeconds: Long = 300L

  private def invalid(reason: String): OAuth2Error = OAuth2Error.InvalidDpopProof(Some(reason))
}
