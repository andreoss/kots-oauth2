package kots.oauth2.host

import cats.effect.IO
import cats.effect.IOApp
import cats.effect.kernel.Resource
import cats.syntax.all._
import com.comcast.ip4s.Port

import kots.oauth2.core.Issuer
import kots.oauth2.server.AssertionIssuers
import org.http4s.ember.client.EmberClientBuilder

object DevServer extends IOApp.Simple {

  val DefaultPort: Int = 8080

  val TrustedIssuersVariable: String = "OAUTH2_TRUSTED_ISSUERS"

  def run: IO[Unit] = serve(DefaultPort)

  def serve(port: Int): IO[Unit] =
    Port
      .fromInt(port)
      .fold(IO.raiseError[Unit](new IllegalStateException("no port")))(bound =>
        assertionIssuers.use(issuers => Development.server[IO](bound, issuers).useForever)
      )

  def trusted(configured: Option[String]): Either[String, List[Issuer]] =
    configured.map(_.split(',').toList.map(_.trim).filter(_.nonEmpty)).getOrElse(Nil) match {
      case Nil    => Right(Nil)
      case values => values.traverse(raw => Issuer.from(raw).leftMap(_ => raw))
    }

  private def assertionIssuers: Resource[IO, Option[AssertionIssuers[IO]]] =
    Resource.eval(IO(sys.env.get(TrustedIssuersVariable))).flatMap { configured =>
      trusted(configured) match {
        case Left(raw)     => Resource.eval(IO.raiseError(new IllegalStateException(s"not an issuer: $raw")))
        case Right(Nil)    => Resource.pure[IO, Option[AssertionIssuers[IO]]](None)
        case Right(values) =>
          EmberClientBuilder
            .default[IO]
            .build
            .evalMap(transport =>
              DiscoveredIssuers
                .create[IO](transport, Development.systemClock[IO], values)
                .map(Some(_): Option[AssertionIssuers[IO]])
            )
      }
    }
}
