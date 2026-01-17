package dev.oauth2.host

import cats.effect.IO
import cats.effect.IOApp
import com.comcast.ip4s.Port

object DevServer extends IOApp.Simple {

  val DefaultPort: Int = 8080

  def run: IO[Unit] = serve(DefaultPort)

  def serve(port: Int): IO[Unit] =
    Port
      .fromInt(port)
      .fold(IO.raiseError[Unit](new IllegalStateException("no port")))(bound =>
        Development.server[IO](bound).useForever
      )
}
