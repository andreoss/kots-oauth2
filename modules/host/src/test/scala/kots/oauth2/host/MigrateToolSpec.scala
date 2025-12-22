package kots.oauth2.host

import java.util.concurrent.atomic.AtomicInteger

import cats.effect.ExitCode
import munit.CatsEffectSuite

class MigrateToolSpec extends CatsEffectSuite {

  private val databases = new AtomicInteger(0)

  private def url: String = {
    Class.forName("org.h2.Driver")
    s"jdbc:h2:mem:migrate-${databases.get};DB_CLOSE_DELAY=-1"
  }

  override def beforeEach(context: BeforeEach): Unit = {
    databases.incrementAndGet()
    ()
  }

  test("a fresh database reports version zero with every migration pending") {
    for {
      version <- MigrateTool.run(List("version", url))
      next <- MigrateTool.run(List("next", url))
    } yield {
      assertEquals(version, ExitCode.Success)
      assertEquals(next, ExitCode.Success)
    }
  }

  test("applying migrates to the last version and verifies afterwards") {
    for {
      applied <- MigrateTool.run(List("apply", url))
      verified <- MigrateTool.run(List("verify", url))
      again <- MigrateTool.run(List("apply", url))
    } yield {
      assertEquals(applied, ExitCode.Success)
      assertEquals(verified, ExitCode.Success)
      assertEquals(again, ExitCode.Success)
    }
  }

  test("a wrong invocation prints the usage and fails") {
    for {
      bare <- MigrateTool.run(Nil)
      unknown <- MigrateTool.run(List("frobnicate", url))
    } yield {
      assertEquals(bare, ExitCode.Error)
      assertEquals(unknown, ExitCode.Error)
    }
  }

  test("an unreachable database fails without raising") {
    MigrateTool
      .run(List("version", "jdbc:unknown:nowhere"))
      .map(assertEquals(_, ExitCode.Error))
  }
}
