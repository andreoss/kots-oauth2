package kots.oauth2.host

import cats.effect.Async
import kots.oauth2.core.OAuth2Error
import kots.oauth2.http.Endpoints
import org.http4s.HttpRoutes
import sttp.model.StatusCode
import sttp.tapir.header
import sttp.tapir.json.circe.jsonBody
import sttp.tapir.server.ServerEndpoint
import sttp.tapir.server.http4s.Http4sServerInterpreter
import sttp.tapir.server.http4s.Http4sServerOptions
import sttp.tapir.server.interceptor.exception.ExceptionHandler
import sttp.tapir.server.model.ValuedEndpointOutput
import sttp.tapir.statusCode

object Interpreter {

  def routes[F[_]: Async](endpoints: List[ServerEndpoint[Any, F]]): HttpRoutes[F] =
    Http4sServerInterpreter[F](options[F]).toRoutes(endpoints)

  private def options[F[_]: Async]: Http4sServerOptions[F] =
    Http4sServerOptions
      .customiseInterceptors[F]
      .exceptionHandler(ExceptionHandler.pure[F](_ => Some(failure)))
      .options

  private def failure: ValuedEndpointOutput[(StatusCode, Map[String, String])] = {
    val error: OAuth2Error = OAuth2Error.ServerError()
    ValuedEndpointOutput(
      statusCode
        .and(header(Endpoints.CacheControlHeader, Endpoints.NoStore))
        .and(jsonBody[Map[String, String]]),
      (StatusCode(error.status), error.body)
    )
  }
}
