package dev.oauth2.client

import java.net.URLDecoder

import cats.effect.IO
import dev.oauth2.core.ClientId
import dev.oauth2.core.CodeChallengeMethod
import dev.oauth2.core.EndpointUri
import dev.oauth2.core.Entropy
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Pkce
import dev.oauth2.core.RedirectUri
import dev.oauth2.core.ResourceIndicator
import dev.oauth2.core.Scopes
import munit.CatsEffectSuite

class AuthorizationUrlsSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val endpoint: EndpointUri = unsafe(EndpointUri.from("https://server.example/authorize"))

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private val entropy: Entropy[IO] = {
    var calls = 0
    new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO {
        calls += 1
        Array.fill(n)(calls.toByte)
      }
    }
  }

  private def query(location: String): Map[String, String] =
    location
      .dropWhile(_ != '?')
      .drop(1)
      .split('&')
      .toList
      .map { pair =>
        val split = pair.split("=", 2)
        split(0) -> URLDecoder.decode(split(1), "UTF-8")
      }
      .toMap

  test("a begun authorization carries the code request with a fresh pkce pair and state") {
    val urls = new AuthorizationUrls[IO](entropy, endpoint)
    for {
      begun <- urls.begin(clientId, callback, unsafe(Scopes.parse("read write")))
    } yield {
      val ticket = begun.toOption.get
      assert(ticket.location.startsWith("https://server.example/authorize?"))
      val fields = query(ticket.location)
      assertEquals(fields.get("response_type"), Some("code"))
      assertEquals(fields.get("client_id"), Some(clientId.value))
      assertEquals(fields.get("redirect_uri"), Some(callback.value))
      assertEquals(fields.get("scope").map(_.split(' ').toSet), Some(Set("read", "write")))
      assertEquals(fields.get("state"), Some(ticket.state.value))
      assertEquals(fields.get("code_challenge_method"), Some("S256"))
      val challenge = unsafe(dev.oauth2.core.CodeChallenge.from(fields("code_challenge")))
      assertEquals(Pkce.verify(Pkce(challenge, CodeChallengeMethod.S256), ticket.verifier), Right(()))
    }
  }

  test("a resource indicator is carried and an empty scope is omitted") {
    val urls = new AuthorizationUrls[IO](entropy, endpoint)
    for {
      begun <- urls.begin(
        clientId,
        callback,
        Scopes.empty,
        Some(unsafe(ResourceIndicator.from("https://api.example")))
      )
    } yield {
      val fields = query(begun.toOption.get.location)
      assertEquals(fields.get("resource"), Some("https://api.example"))
      assertEquals(fields.get("scope"), None)
    }
  }

  test("every begun authorization draws a distinct verifier and state") {
    val urls = new AuthorizationUrls[IO](entropy, endpoint)
    for {
      first <- urls.begin(clientId, callback, Scopes.empty)
      second <- urls.begin(clientId, callback, Scopes.empty)
    } yield {
      assert(first.toOption.get.verifier != second.toOption.get.verifier)
      assert(first.toOption.get.state != second.toOption.get.state)
    }
  }
}
