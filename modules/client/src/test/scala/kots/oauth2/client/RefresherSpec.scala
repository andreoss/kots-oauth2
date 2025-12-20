package kots.oauth2.client

import scala.concurrent.duration._

import cats.effect.IO
import cats.effect.kernel.Ref
import cats.effect.testkit.TestControl
import cats.syntax.parallel._
import kots.oauth2.core.AccessToken
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.Scopes
import munit.CatsEffectSuite

class RefresherSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val first: RefreshToken = unsafe(RefreshToken.from("rt-1"))

  private val second: RefreshToken = unsafe(RefreshToken.from("rt-2"))

  private val granted: TokenClient.Grant =
    TokenClient.Grant(unsafe(AccessToken.from("at-1")), "Bearer", 3600L, None, Scopes.empty)

  test("concurrent refreshes of one token share a single flight") {
    val outcome = for {
      calls <- Ref.of[IO, Int](0)
      refresher <- Refresher.create[IO](_ => calls.update(_ + 1) >> IO.sleep(1.second).as(Right(granted)))
      results <- (refresher.refresh(first), refresher.refresh(first)).parTupled
      count <- calls.get
    } yield (results, count)
    TestControl.executeEmbed(outcome).map { case ((one, other), count) =>
      assertEquals(one, Right(granted))
      assertEquals(other, Right(granted))
      assertEquals(count, 1)
    }
  }

  test("distinct tokens fly separately") {
    val outcome = for {
      calls <- Ref.of[IO, Int](0)
      refresher <- Refresher.create[IO](_ => calls.update(_ + 1) >> IO.sleep(1.second).as(Right(granted)))
      _ <- (refresher.refresh(first), refresher.refresh(second)).parTupled
      count <- calls.get
    } yield count
    TestControl.executeEmbed(outcome).map(count => assertEquals(count, 2))
  }

  test("a transient failure is retried with a doubling backoff") {
    val outcome = for {
      answers <- Ref.of[IO, List[Either[OAuth2Error, TokenClient.Grant]]](
        List(
          Left(OAuth2Error.ServerError()),
          Left(OAuth2Error.TemporarilyUnavailable()),
          Right(granted)
        )
      )
      calls <- Ref.of[IO, Int](0)
      refresher <- Refresher.create[IO] { _ =>
        calls.update(_ + 1) >> answers.modify {
          case head :: tail => (tail, head)
          case Nil          => (Nil, Left(OAuth2Error.ServerError()))
        }
      }
      begun <- IO.monotonic
      answered <- refresher.refresh(first)
      finished <- IO.monotonic
      count <- calls.get
    } yield (answered, count, finished - begun)
    TestControl.executeEmbed(outcome).map { case (answered, count, elapsed) =>
      assertEquals(answered, Right(granted))
      assertEquals(count, 3)
      assertEquals(elapsed, 3.seconds)
    }
  }

  test("a terminal refusal is never retried") {
    val outcome = for {
      calls <- Ref.of[IO, Int](0)
      refresher <- Refresher.create[IO](_ => calls.update(_ + 1).as(Left(OAuth2Error.InvalidGrant())))
      answered <- refresher.refresh(first)
      count <- calls.get
    } yield (answered, count)
    TestControl.executeEmbed(outcome).map { case (answered, count) =>
      assertEquals(answered, Left(OAuth2Error.InvalidGrant()))
      assertEquals(count, 1)
    }
  }

  test("retries give up after the bounded attempts") {
    val outcome = for {
      calls <- Ref.of[IO, Int](0)
      refresher <- Refresher.create[IO](_ => calls.update(_ + 1).as(Left(OAuth2Error.ServerError())))
      begun <- IO.monotonic
      answered <- refresher.refresh(first)
      finished <- IO.monotonic
      count <- calls.get
    } yield (answered, count, finished - begun)
    TestControl.executeEmbed(outcome).map { case (answered, count, elapsed) =>
      assertEquals(answered.left.toOption.map(_.code), Some("server_error"))
      assertEquals(count, 1 + Refresher.Retries)
      assertEquals(elapsed, 7.seconds)
    }
  }

  test("a finished flight makes room for the next refresh of the same token") {
    val outcome = for {
      calls <- Ref.of[IO, Int](0)
      refresher <- Refresher.create[IO](_ => calls.update(_ + 1).as(Right(granted)))
      _ <- refresher.refresh(first)
      _ <- refresher.refresh(first)
      count <- calls.get
    } yield count
    TestControl.executeEmbed(outcome).map(count => assertEquals(count, 2))
  }
}
