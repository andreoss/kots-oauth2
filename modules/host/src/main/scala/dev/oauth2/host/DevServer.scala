package dev.oauth2.host

import cats.effect.IO
import cats.effect.IOApp
import com.comcast.ip4s.Port

object DevServer extends IOApp.Simple {

  val DefaultPort: Int = 8080

  def run: IO[Unit] =
    Port
      .fromInt(DefaultPort)
      .fold(IO.raiseError[Unit](new IllegalStateException("no port")))(port =>
        Development.server[IO](port).useForever
      )
}
