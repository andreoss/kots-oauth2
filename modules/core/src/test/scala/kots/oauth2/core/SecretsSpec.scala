package kots.oauth2.core

import java.nio.charset.StandardCharsets
import java.util.Base64

import org.scalacheck.Gen
import org.scalacheck.Prop._
import munit.ScalaCheckSuite

class SecretsSpec extends ScalaCheckSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private def secret(raw: String): ClientSecret = unsafe(ClientSecret.from(raw))

  private def basic(id: String, secret: String): String =
    Base64.getEncoder.encodeToString(s"$id:$secret".getBytes(StandardCharsets.UTF_8))

  private val secretText: Gen[String] =
    Gen
      .choose(8, 64)
      .flatMap(n => Gen.listOfN(n, Gen.oneOf(Gen.alphaNumChar, Gen.oneOf('-', '.', '_', '~'))))
      .map(_.mkString)

  test("the hash of a secret verifies that secret") {
    val value = secret("s3cr3t-value")
    assert(ClientSecretHash.verify(ClientSecretHash.of(value), value))
  }

  test("the hash of a secret refuses another secret") {
    val value = secret("s3cr3t-value")
    val other = secret("s3cr3t-other")
    assert(!ClientSecretHash.verify(ClientSecretHash.of(value), other))
  }

  test("the hash is not the secret itself") {
    val value = secret("s3cr3t-value")
    assertNotEquals(ClientSecretHash.of(value).value, value.value)
  }

  test("the hash has the length of a SHA-256 digest in hex") {
    val value = secret("s3cr3t-value")
    assertEquals(ClientSecretHash.of(value).value.length, 64)
  }

  test("basic credentials round trip") {
    val parsed = ClientCredentials.fromBasic(basic("client-1", "s3cr3t"))
    assertEquals(parsed.map(_.id), Right(unsafe(ClientId.from("client-1"))))
    assertEquals(parsed.map(_.secret), Right(secret("s3cr3t")))
  }

  test("basic credentials decode a percent encoded secret") {
    val header = Base64.getEncoder.encodeToString("client-1:s3%2Fcr3t".getBytes(StandardCharsets.UTF_8))
    assertEquals(ClientCredentials.fromBasic(header).map(_.secret), Right(secret("s3/cr3t")))
  }

  test("basic credentials refuse a value without a separator") {
    val header = Base64.getEncoder.encodeToString("client-1".getBytes(StandardCharsets.UTF_8))
    assert(ClientCredentials.fromBasic(header).isLeft)
  }

  test("basic credentials refuse a value that is not base64") {
    assert(ClientCredentials.fromBasic("not base64 !").isLeft)
  }

  test("basic credentials refuse an empty secret") {
    assert(ClientCredentials.fromBasic(basic("client-1", "")).isLeft)
  }

  test("a secret refuses empty and unprintable text") {
    assert(ClientSecret.from("").isLeft)
    assert(ClientSecret.from("has space").isLeft)
  }

  property("the hash of a secret refuses every other secret") {
    forAll(secretText, secretText) { (one, two) =>
      one == two || !ClientSecretHash.verify(ClientSecretHash.of(secret(one)), secret(two))
    }
  }

  property("hashing is deterministic") {
    forAll(secretText) { raw =>
      ClientSecretHash.of(secret(raw)).value == ClientSecretHash.of(secret(raw)).value
    }
  }

  test("a stored secret hash rehydrates only from a sha-256 hex value") {
    val hash = ClientSecretHash.of(secret("s3cret"))
    assertEquals(ClientSecretHash.fromStored(hash.value), Right(hash))
    assert(ClientSecretHash.fromStored("nothex").isLeft)
    val registration = RegistrationTokenHash.of(RegistrationToken.from("registration-1").toOption.get)
    assertEquals(RegistrationTokenHash.fromStored(registration.value), Right(registration))
    assert(RegistrationTokenHash.fromStored("A" * 64).isLeft)
  }
}
