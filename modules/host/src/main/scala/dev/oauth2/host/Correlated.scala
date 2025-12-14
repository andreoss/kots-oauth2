package dev.oauth2.host

import cats.Monad
import cats.data.Kleisli
import cats.data.OptionT
import cats.syntax.functor._

import dev.oauth2.core.Entropy
import org.http4s.HttpRoutes
import org.http4s.Request
import org.typelevel.ci.CIString

object Correlated {

  val Header: String = "X-Request-Id"

  val IdBytes: Int = 16

  def apply[F[_]: Monad](entropy: Entropy[F], routes: HttpRoutes[F]): HttpRoutes[F] =
    Kleisli { request =>
      OptionT.liftF(idOf(entropy, request)).flatMap { id =>
        routes
          .run(request.putHeaders(raw(id)))
          .map(_.putHeaders(raw(id)))
      }
    }

  private def raw(id: String): org.http4s.Header.Raw =
    org.http4s.Header.Raw(CIString(Header), id)

  private def idOf[F[_]: Monad](entropy: Entropy[F], request: Request[F]): F[String] =
    request.headers.get(CIString(Header)).map(_.head.value) match {
      case Some(carried) => Monad[F].pure(carried)
      case None          => entropy.bytes(IdBytes).map(Entropy.hex)
    }
}
