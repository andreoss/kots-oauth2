package dev.oauth2.host

import cats.effect.Async
import org.http4s.HttpRoutes
import sttp.tapir.server.ServerEndpoint
import sttp.tapir.server.http4s.Http4sServerInterpreter

object Interpreter {

  def routes[F[_]: Async](endpoints: List[ServerEndpoint[Any, F]]): HttpRoutes[F] =
    Http4sServerInterpreter[F]().toRoutes(endpoints)
}
