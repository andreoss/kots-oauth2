package kots.oauth2.host

import scala.concurrent.duration._

import cats.effect.IO
import cats.effect.kernel.Ref
import cats.effect.testkit.TestControl
import munit.CatsEffectSuite

class SweeperSpec extends CatsEffectSuite {

  test("the sweeper runs every store on each interval and sums the evictions") {
    val outcome = for {
      calls <- Ref.of[IO, Int](0)
      swept <- Sweeper
        .stream[IO](10.seconds, List(calls.update(_ + 1).as(2), calls.update(_ + 1).as(3)))
        .take(2)
        .compile
        .toList
      count <- calls.get
    } yield (swept, count)
    TestControl.executeEmbed(outcome).map { case (swept, count) =>
      assertEquals(swept, List(5, 5))
      assertEquals(count, 4)
    }
  }
}
