package kots.oauth2.host

import cats.data.Kleisli
import cats.data.OptionT
import cats.effect.IO
import cats.effect.kernel.Ref
import kots.oauth2.core.Entropy
import munit.CatsEffectSuite
import org.http4s.HttpRoutes
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.Uri
import org.typelevel.ci.CIString

class CorrelatedSpec extends CatsEffectSuite {

  private val entropy: Entropy[IO] =
    new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO.pure(Array.fill(n)(7.toByte))
    }

  private def request(headers: (String, String)*): Request[IO] =
    Request[IO](
      method = Method.GET,
      uri = Uri.unsafeFromString("http://localhost/anything"),
      headers = org.http4s.Headers(headers.map { case (name, value) =>
        org.http4s.Header.Raw(CIString(name), value)
      }.toList)
    )

  private def seenBy(seen: Ref[IO, Option[String]]): HttpRoutes[IO] =
    Kleisli { incoming =>
      OptionT.liftF(
        seen
          .set(incoming.headers.get(CIString(Correlated.Header)).map(_.head.value))
          .as(Response[IO](Status.Ok))
      )
    }

  private def answered(response: Option[Response[IO]]): Option[String] =
    response.flatMap(_.headers.get(CIString(Correlated.Header)).map(_.head.value))

  test("a request without a correlation id is given one for the whole path") {
    for {
      seen <- Ref.of[IO, Option[String]](None)
      correlated = Correlated(entropy, seenBy(seen))
      response <- correlated.run(request()).value
      inside <- seen.get
    } yield {
      val echoed = answered(response)
      assert(echoed.exists(_.length == Correlated.IdBytes * 2))
      assertEquals(inside, echoed)
    }
  }

  test("a carried correlation id is preserved and echoed unchanged") {
    for {
      seen <- Ref.of[IO, Option[String]](None)
      correlated = Correlated(entropy, seenBy(seen))
      response <- correlated.run(request(Correlated.Header -> "corr-1")).value
      inside <- seen.get
    } yield {
      assertEquals(answered(response), Some("corr-1"))
      assertEquals(inside, Some("corr-1"))
    }
  }
}
