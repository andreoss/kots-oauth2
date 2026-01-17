package dev.oauth2.host

import scala.concurrent.duration._

import cats.effect.IO
import munit.CatsEffectSuite

class DevServerSpec extends CatsEffectSuite {

  test("the served application stays up until it is shut down") {
    DevServer.serve(0).race(IO.sleep(250.millis)).map(outcome => assertEquals(outcome, Right(())))
  }

  test("a port outside the allowed range is refused") {
    interceptIO[IllegalStateException](DevServer.serve(70000))
  }

  test("the default port is the conventional development port") {
    assertEquals(DevServer.DefaultPort, 8080)
  }
}
