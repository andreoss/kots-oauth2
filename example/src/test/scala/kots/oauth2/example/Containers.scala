package kots.oauth2.example

import scala.concurrent.duration._

import cats.effect.IO
import cats.effect.kernel.Resource
import org.http4s.Request
import org.http4s.Uri
import org.http4s.client.Client

object Containers {

  val Flag: String = "OAUTH2_E2E"

  def enabled: Boolean =
    sys.env.get(Flag).contains("1") && run(List("docker", "version")).exists(_._1 == 0)

  def run(command: List[String]): Option[(Int, String)] =
    scala.util.Try {
      val builder = new ProcessBuilder(command: _*)
      builder.redirectErrorStream(true)
      val process = builder.start()
      val output = new String(process.getInputStream.readAllBytes())
      (process.waitFor(), output)
    }.toOption

  def container(arguments: List[String]): Resource[IO, String] =
    Resource.make(
      IO.blocking {
        val started = run("docker" :: "run" :: "-d" :: "--rm" :: arguments)
        started match {
          case Some((0, output)) =>
            output.linesIterator
              .map(_.trim)
              .filter(_.nonEmpty)
              .toList
              .lastOption
              .getOrElse(sys.error("container id missing"))
          case other => sys.error(s"container did not start: $other")
        }
      }
    )(id => IO.blocking(run(List("docker", "rm", "-f", id))).void)

  def awaitHttp(transport: Client[IO], url: String, remaining: Int = 600): IO[Unit] =
    transport
      .status(Request[IO](uri = Uri.unsafeFromString(url)))
      .map(_.isSuccess)
      .handleError(_ => false)
      .flatMap { ready =>
        if (ready) IO.unit
        else if (remaining <= 0) IO.raiseError(new IllegalStateException(s"$url never became ready"))
        else IO.sleep(500.millis) >> awaitHttp(transport, url, remaining - 1)
      }
}
