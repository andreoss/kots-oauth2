package kots.oauth2.host

import cats.effect.ExitCode
import munit.CatsEffectSuite

class KeysToolSpec extends CatsEffectSuite {

  test("the generate command prints a key set and succeeds") {
    KeysTool.run(List("generate")).map(assertEquals(_, ExitCode.Success))
  }

  test("the rotate command retires the current key and succeeds") {
    KeysTool.run(List("rotate")).map(assertEquals(_, ExitCode.Success))
  }

  test("an unknown command prints the usage and fails") {
    KeysTool.run(List("frobnicate")).map(assertEquals(_, ExitCode.Error))
  }
}
