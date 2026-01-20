package kots.oauth2.client

import scala.concurrent.duration._

import cats.effect.IO
import cats.effect.kernel.Ref
import cats.effect.testkit.TestControl
import kots.oauth2.core.AccessToken
import kots.oauth2.core.Lifetime
import kots.oauth2.core.OAuth2Error
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import munit.CatsEffectSuite

class DevicePollerSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val interval: Lifetime = unsafe(Lifetime.fromSeconds(5L))

  private val granted: TokenClient.Grant =
    TokenClient.Grant(unsafe(AccessToken.from("at-1")), "Bearer", 3600L, None, Scopes.empty)

  private def scripted(
      answers: List[Either[OAuth2Error, TokenClient.Grant]]
  ): IO[(IO[Either[OAuth2Error, TokenClient.Grant]], IO[Int])] =
    Ref.of[IO, List[Either[OAuth2Error, TokenClient.Grant]]](answers).map { remaining =>
      val poll = remaining.modify {
        case head :: tail => (tail, head)
        case Nil          => (Nil, Left(OAuth2Error.ServerError(Some("exhausted"))))
      }
      (poll, remaining.get.map(answers.length - _.length))
    }

  test("the poller waits the interval between pending polls and ends on the grant") {
    val outcome = for {
      pair <- scripted(
        List(
          Left(OAuth2Error.AuthorizationPending()),
          Left(OAuth2Error.AuthorizationPending()),
          Right(granted)
        )
      )
      (poll, polled) = pair
      begun <- IO.monotonic
      answered <- DevicePoller.await[IO](interval)(poll)
      finished <- IO.monotonic
      count <- polled
    } yield (answered, count, finished - begun)
    TestControl.executeEmbed(outcome).map { case (answered, count, elapsed) =>
      assertEquals(answered, Right(granted))
      assertEquals(count, 3)
      assertEquals(elapsed, 10.seconds)
    }
  }

  test("a slow down answer grows the interval by five seconds") {
    val outcome = for {
      pair <- scripted(
        List(
          Left(OAuth2Error.SlowDown()),
          Left(OAuth2Error.AuthorizationPending()),
          Right(granted)
        )
      )
      (poll, _) = pair
      begun <- IO.monotonic
      answered <- DevicePoller.await[IO](interval)(poll)
      finished <- IO.monotonic
    } yield (answered, finished - begun)
    TestControl.executeEmbed(outcome).map { case (answered, elapsed) =>
      assertEquals(answered, Right(granted))
      assertEquals(elapsed, 20.seconds)
    }
  }

  test("a terminal refusal ends the polling at once") {
    val outcome = for {
      pair <- scripted(List(Left(OAuth2Error.AccessDenied()), Right(granted)))
      (poll, polled) = pair
      answered <- DevicePoller.await[IO](interval)(poll)
      count <- polled
    } yield (answered, count)
    TestControl.executeEmbed(outcome).map { case (answered, count) =>
      assertEquals(answered, Left(OAuth2Error.AccessDenied()))
      assertEquals(count, 1)
    }
  }

  test("the grown interval adds five seconds only on a slow down") {
    assertEquals(DevicePoller.next(interval, slowedDown = false), interval)
    assertEquals(DevicePoller.next(interval, slowedDown = true).seconds, 10L)
  }
}
