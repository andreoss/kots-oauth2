package kots.oauth2.host

import java.io.File
import java.net.Socket

import scala.concurrent.duration._

import cats.effect.IO
import cats.effect.kernel.Resource
import com.comcast.ip4s.Port
import kots.oauth2.client.TokenClient
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.ParseFailure
import munit.CatsEffectSuite
import org.http4s.ember.client.EmberClientBuilder

class InteropSpec extends CatsEffectSuite {

  override def munitIOTimeout: Duration = 3.minutes

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val root: Option[File] =
    Iterator
      .iterate(new File(".").getAbsoluteFile)(_.getParentFile)
      .takeWhile(_ != null)
      .find(dir => new File(dir, "references/server/oauth2").isDirectory)

  private def runnable: Boolean =
    root.isDefined && run(new File("."), List("go", "version")).exists(_._1 == 0)

  private def run(cwd: File, command: List[String]): Option[(Int, String)] =
    scala.util.Try {
      val builder = new ProcessBuilder(command: _*)
      builder.directory(cwd)
      builder.redirectErrorStream(true)
      builder.environment().put("GOTELEMETRY", "off")
      val process = builder.start()
      val output = new String(process.getInputStream.readAllBytes())
      (process.waitFor(), output)
    }.toOption

  private def built(module: File, target: String, sources: String): Option[File] = {
    val binary = new File(module, s"target-interop/$target")
    binary.getParentFile.mkdirs()
    run(module, List("go", "build", "-o", binary.getAbsolutePath, sources))
      .filter(_._1 == 0)
      .map(_ => binary)
  }

  private def awaitPort(port: Int): IO[Unit] =
    IO.blocking(scala.util.Try(new Socket("localhost", port).close()).isSuccess)
      .flatMap(open => if (open) IO.unit else IO.sleep(200.millis) >> awaitPort(port))

  private def spawned(binary: File, arguments: List[String]): Resource[IO, Process] =
    Resource.make(
      IO.blocking {
        val builder = new ProcessBuilder((binary.getAbsolutePath :: arguments): _*)
        builder.redirectErrorStream(true)
        builder.start()
      }
    )(process => IO.blocking(process.destroy()))

  test("the token client obtains a grant from the independent authorization server") {
    assume(runnable, "the go toolchain or the reference implementation is not available")
    val references = new File(root.get, "references/server/oauth2")
    val binary = built(references, "authserver", "./example/server")
    assume(binary.isDefined, "the reference server does not build")
    spawned(binary.get, List("-d=false", "-p", "9097"))
      .use { _ =>
        awaitPort(9097) >>
          EmberClientBuilder.default[IO].build.use { transport =>
            new TokenClient[IO](transport, unsafe(EndpointUri.from("http://localhost:9097/oauth/token")))
              .clientCredentials(
                unsafe(ClientId.from("222222")),
                unsafe(ClientSecret.from("22222222")),
                None
              )
          }
      }
      .map { answered =>
        val grant = answered.toOption.get
        assertEquals(grant.tokenType, "Bearer")
        assert(grant.accessToken.value.nonEmpty)
        assert(grant.expiresIn > 0L)
      }
  }

  test("the independent client obtains a grant from the served authorization server") {
    assume(runnable, "the go toolchain or the reference implementation is not available")
    val interop = new File(root.get, "example/interop")
    val binary = built(interop, "token-client", ".")
    assume(binary.isDefined, "the interop client does not build")
    Development
      .server[IO](Port.fromInt(0).get)
      .use { server =>
        IO.blocking(
          run(
            interop,
            List(
              binary.get.getAbsolutePath,
              s"http://localhost:${server.address.getPort}/token",
              Development.SeedClientId,
              Development.SeedClientSecret
            )
          )
        )
      }
      .map { outcome =>
        val (code, output) = outcome.get
        assertEquals(code, 0, output)
        assert(output.contains("token_type: Bearer"))
        assert(output.contains("access_token_present: true"))
      }
  }
}
