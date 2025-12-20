package kots.oauth2.client

import java.time.Instant

import cats.effect.IO
import cats.effect.kernel.Ref

import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.Clock
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.Entropy
import kots.oauth2.core.ParseFailure
import kots.oauth2.jose.Dpop
import kots.oauth2.jose.Fakes
import munit.CatsEffectSuite
import org.http4s.Charset
import org.http4s.Header
import org.http4s.HttpApp
import org.http4s.Response
import org.http4s.Status
import org.http4s.client.Client
import org.typelevel.ci.CIString

class DpopSignerSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private val endpoint: EndpointUri = unsafe(EndpointUri.from("https://server.example/token"))

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val secret: ClientSecret = unsafe(ClientSecret.from("s3cret"))

  private val grantBody: String =
    """{"access_token":"at-1","token_type":"DPoP","expires_in":"3600"}"""

  private val nonceBody: String = """{"error":"use_dpop_nonce"}"""

  private val entropy: Entropy[IO] = {
    var calls = 0
    new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO {
        calls += 1
        Array.fill(n)(calls.toByte)
      }
    }
  }

  private val clock: Clock[IO] =
    new Clock[IO] {
      def instant: IO[Instant] = IO.pure(Start)
    }

  private def signer: IO[DpopSigner[IO]] =
    DpopSigner.create[IO](
      entropy,
      clock,
      Fakes.signingKey.alg,
      Fakes.signingPair.getPrivate,
      Fakes.signingJwk
    )

  test("every minted proof is fresh and names the request line") {
    for {
      minted <- signer
      first <- minted.proof("POST", endpoint.value)
      second <- minted.proof("POST", endpoint.value)
    } yield {
      val one = Dpop.verify(first.toOption.get).toOption.get
      val two = Dpop.verify(second.toOption.get).toOption.get
      assertEquals(one.method, "POST")
      assertEquals(one.uri, endpoint.value)
      assertEquals(one.issuedAt, Start)
      assertEquals(one.nonce, None)
      assert(one.jti != two.jti)
    }
  }

  test("a learned nonce is carried on later proofs") {
    for {
      minted <- signer
      _ <- minted.learn(Some("n-1"))
      compact <- minted.proof("POST", endpoint.value)
    } yield assertEquals(Dpop.verify(compact.toOption.get).toOption.get.nonce, Some("n-1"))
  }

  private def ok(body: String): Response[IO] =
    Response[IO](Status.Ok).withEntity(body)(org.http4s.EntityEncoder.stringEncoder(Charset.`UTF-8`))

  private def demanding(seen: Ref[IO, List[Option[String]]]): Client[IO] =
    Client.fromHttpApp(HttpApp[IO] { request =>
      val nonce = request.headers
        .get(CIString("DPoP"))
        .map(_.head.value)
        .flatMap(compact => Dpop.verify(compact).toOption.flatMap(_.nonce))
      seen.update(_ :+ nonce).map { _ =>
        if (nonce.contains("n-1")) ok(grantBody)
        else
          Response[IO](Status.BadRequest)
            .withEntity(nonceBody)(org.http4s.EntityEncoder.stringEncoder(Charset.`UTF-8`))
            .putHeaders(Header.Raw(CIString("DPoP-Nonce"), "n-1"))
      }
    })

  test("a nonce demand is answered by one retry carrying the demanded nonce") {
    for {
      seen <- Ref.of[IO, List[Option[String]]](List.empty)
      minted <- signer
      tokens = new TokenClient[IO](demanding(seen), endpoint, Some(minted))
      granted <- tokens.clientCredentials(clientId, secret, None)
      calls <- seen.get
    } yield {
      assertEquals(granted.toOption.map(_.tokenType), Some("DPoP"))
      assertEquals(calls, List(None, Some("n-1")))
    }
  }

  test("a learned nonce is reused without another demand") {
    for {
      seen <- Ref.of[IO, List[Option[String]]](List.empty)
      minted <- signer
      tokens = new TokenClient[IO](demanding(seen), endpoint, Some(minted))
      _ <- tokens.clientCredentials(clientId, secret, None)
      again <- tokens.clientCredentials(clientId, secret, None)
      calls <- seen.get
    } yield {
      assertEquals(again.toOption.map(_.tokenType), Some("DPoP"))
      assertEquals(calls, List(None, Some("n-1"), Some("n-1")))
    }
  }

  test("an unanswered nonce demand is returned after the single retry") {
    val stubborn = Client.fromHttpApp(HttpApp[IO] { _ =>
      IO.pure(
        Response[IO](Status.BadRequest)
          .withEntity(nonceBody)(org.http4s.EntityEncoder.stringEncoder(Charset.`UTF-8`))
      )
    })
    for {
      minted <- signer
      tokens = new TokenClient[IO](stubborn, endpoint, Some(minted))
      refused <- tokens.clientCredentials(clientId, secret, None)
    } yield assert(refused.left.toOption.exists(_.code == "use_dpop_nonce"))
  }
}
