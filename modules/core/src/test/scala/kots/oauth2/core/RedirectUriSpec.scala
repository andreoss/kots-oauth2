package kots.oauth2.core

import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class RedirectUriSpec extends ScalaCheckSuite {

  private def uri(raw: String): RedirectUri =
    RedirectUri.from(raw).fold(e => fail(s"$raw refused: ${e.reason}"), identity)

  private val genHost: Gen[String] =
    Gen.choose(1, 10).flatMap(n => Gen.listOfN(n, Gen.alphaLowerChar)).map(_.mkString)

  private val genPath: Gen[String] = Gen.oneOf("/cb", "/oauth/callback", "/")

  test("https redirect uris round trip") {
    assertEquals(uri("https://example.com/cb").value, "https://example.com/cb")
  }

  test("a wildcard is refused") {
    assert(RedirectUri.from("https://example.com/*").isLeft)
    assert(RedirectUri.from("https://*.example.com/cb").isLeft)
    assert(RedirectUri.from("https://example.com/cb?a=*").isLeft)
  }

  test("a fragment is refused") {
    assert(RedirectUri.from("https://example.com/cb#f").isLeft)
  }

  test("userinfo is refused") {
    assert(RedirectUri.from("https://user:pass@example.com/cb").isLeft)
    assert(RedirectUri.from("https://user@example.com/cb").isLeft)
  }

  test("http is allowed on the loopback only") {
    assert(RedirectUri.from("http://127.0.0.1:8080/cb").isRight)
    assert(RedirectUri.from("http://[::1]:9000/cb").isRight)
    assert(RedirectUri.from("http://localhost/cb").isRight)
    assert(RedirectUri.from("http://example.com/cb").isLeft)
    assert(RedirectUri.from("http://10.0.0.1/cb").isLeft)
  }

  test("https requires a host") {
    assert(RedirectUri.from("https:/cb").isLeft)
  }

  test("native schemes follow reverse domain name notation") {
    assert(RedirectUri.from("com.example.app:/oauth2redirect").isRight)
    assert(RedirectUri.from("myapp:/cb").isLeft)
    assert(RedirectUri.from("myapp:cb").isLeft)
  }

  test("schemes that enable an open redirector are refused") {
    assert(RedirectUri.from("javascript:alert(1)").isLeft)
    assert(RedirectUri.from("data:text/html,redirect").isLeft)
    assert(RedirectUri.from("file:///etc/passwd").isLeft)
  }

  test("matching is exact for registered uris") {
    val registered = Set(uri("https://example.com/cb"))
    assert(RedirectUri.matches(registered, uri("https://example.com/cb")))
    assert(!RedirectUri.matches(registered, uri("https://example.com/cb/extra")))
    assert(!RedirectUri.matches(registered, uri("https://example.com/CB")))
    assert(!RedirectUri.matches(registered, uri("https://example.com/cb?a=b")))
    assert(!RedirectUri.matches(registered, uri("https://other.example.com/cb")))
    assert(!RedirectUri.matches(Set.empty[RedirectUri], uri("https://example.com/cb")))
  }

  test("a loopback redirect matches on any port") {
    val registered = Set(uri("http://127.0.0.1/cb"))
    assert(RedirectUri.matches(registered, uri("http://127.0.0.1:8080/cb")))
    assert(RedirectUri.matches(registered, uri("http://127.0.0.1/cb")))
    assert(!RedirectUri.matches(registered, uri("http://127.0.0.1:8080/other")))
    assert(!RedirectUri.matches(registered, uri("http://localhost:8080/cb")))
  }

  test("a non loopback redirect matches on the port it registered") {
    val registered = Set(uri("https://example.com:8443/cb"))
    assert(RedirectUri.matches(registered, uri("https://example.com:8443/cb")))
    assert(!RedirectUri.matches(registered, uri("https://example.com/cb")))
  }

  test("loopback and native uris are recognised") {
    assert(RedirectUri.isLoopback(uri("http://127.0.0.1:8080/cb")))
    assert(RedirectUri.isLoopback(uri("http://[::1]/cb")))
    assert(RedirectUri.isLoopback(uri("http://localhost/cb")))
    assert(!RedirectUri.isLoopback(uri("https://example.com/cb")))
    assert(RedirectUri.isNativeScheme(uri("com.example.app:/cb")))
    assert(!RedirectUri.isNativeScheme(uri("https://example.com/cb")))
  }

  property("a generated https uri round trips") {
    forAll(genHost, genPath) { (host, path) =>
      RedirectUri.from(s"https://$host$path").map(_.value) == Right(s"https://$host$path")
    }
  }

  property("matching is reflexive and independent of registration order") {
    forAll(genHost, genPath) { (host, path) =>
      val one = Set(uri(s"https://$host$path"))
      val two = one ++ Set(uri(s"https://$host/other"))
      RedirectUri.matches(one, uri(s"https://$host$path")) &&
      RedirectUri.matches(two, uri(s"https://$host$path"))
    }
  }

  property("no uri containing a wildcard is ever accepted") {
    forAll(genHost, genPath) { (host, path) =>
      RedirectUri.from(s"https://$host$path*").isLeft
    }
  }
}
