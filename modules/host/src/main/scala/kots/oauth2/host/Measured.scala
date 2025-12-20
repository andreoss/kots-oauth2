package kots.oauth2.host

import cats.data.Kleisli
import cats.data.OptionT
import cats.effect.Temporal
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.store.Metrics
import kots.oauth2.store.Observation
import org.http4s.HttpRoutes
import org.http4s.Response

object Measured {

  def apply[F[_]: Temporal](metrics: Metrics[F], routes: HttpRoutes[F]): HttpRoutes[F] =
    Kleisli { request =>
      OptionT {
        Temporal[F].monotonic.flatMap { begun =>
          routes.run(request).value.flatMap {
            case Some(response) =>
              Temporal[F].monotonic.flatMap { finished =>
                metrics
                  .observed(
                    Observation(
                      request.uri.path.renderString,
                      response.status.code,
                      (finished - begun).toNanos
                    )
                  )
                  .as(Some(response): Option[Response[F]])
              }
            case None => Temporal[F].pure(None: Option[Response[F]])
          }
        }
      }
    }
}
