package dev.oauth2.server

import java.time.Instant

import cats.effect.IO

import dev.oauth2.core.Clock
import dev.oauth2.core.JwtId
import dev.oauth2.core.ParseFailure
import dev.oauth2.jose.Dpop
import dev.oauth2.jose.Fakes
import dev.oauth2.store.memory.InMemoryReplayStore
import munit.CatsEffectSuite

class DpopProofsSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val Token: String = "https://server.example/token"

  private def clockAt(now: Instant): Clock[IO] =
    new Clock[IO] {
      def instant: IO[Instant] = IO.pure(now)
    }

  private def proofs(now: Instant = Start, nonce: Option[IO[String]] = None): IO[DpopProofs[IO]] =
    InMemoryReplayStore
      .create[IO](clockAt(now))
      .map(replays => new DpopProofs[IO](replays, clockAt(now), nonce))

  private def compact(
      jti: String = "proof-1",
      method: String = "POST",
      uri: String = Token,
      issuedAt: Instant = Start,
      nonce: Option[String] = None
  ): String =
    Dpop
      .prove(
        Fakes.signingKey.alg,
        Fakes.signingPair.getPrivate,
        Fakes.signingJwk,
        unsafe(JwtId.from(jti)),
        method,
        uri,
        issuedAt,
        nonce
      )
      .toOption
      .get

  test("a fresh proof for the request is accepted with the key thumbprint") {
    for {
      validator <- proofs()
      result <- validator.validate(compact(), "POST", Token)
    } yield assertEquals(result.toOption, Dpop.thumbprint(Fakes.signingJwk).toOption)
  }

  test("a proof for another method or uri is refused") {
    for {
      validator <- proofs()
      method <- validator.validate(compact(), "GET", Token)
      uri <- validator.validate(compact(jti = "proof-2"), "POST", "https://other.example/token")
    } yield {
      assert(method.left.toOption.exists(_.code == "invalid_dpop_proof"))
      assert(uri.left.toOption.exists(_.code == "invalid_dpop_proof"))
    }
  }

  test("a proof outside the freshness window is refused") {
    for {
      validator <- proofs(now = Start.plusSeconds(DpopProofs.WindowSeconds + 1L))
      stale <- validator.validate(compact(), "POST", Token)
      ahead <- proofs().flatMap(
        _.validate(compact(issuedAt = Start.plusSeconds(DpopProofs.WindowSeconds + 1L)), "POST", Token)
      )
    } yield {
      assert(stale.left.toOption.exists(_.code == "invalid_dpop_proof"))
      assert(ahead.left.toOption.exists(_.code == "invalid_dpop_proof"))
    }
  }

  test("a replayed proof is refused") {
    for {
      validator <- proofs()
      first <- validator.validate(compact(), "POST", Token)
      second <- validator.validate(compact(), "POST", Token)
    } yield {
      assert(first.isRight)
      assert(second.left.toOption.exists(_.code == "invalid_dpop_proof"))
    }
  }

  test("a demanded nonce is enforced and its absence asks for one") {
    for {
      validator <- proofs(nonce = Some(IO.pure("n-1")))
      missing <- validator.validate(compact(), "POST", Token)
      wrong <- validator.validate(compact(jti = "proof-2", nonce = Some("n-0")), "POST", Token)
      carried <- validator.validate(compact(jti = "proof-3", nonce = Some("n-1")), "POST", Token)
    } yield {
      assert(missing.left.toOption.exists(_.code == "use_dpop_nonce"))
      assert(wrong.left.toOption.exists(_.code == "use_dpop_nonce"))
      assert(carried.isRight)
    }
  }
}
