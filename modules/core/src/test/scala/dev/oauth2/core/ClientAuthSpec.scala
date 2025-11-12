package dev.oauth2.core

import java.nio.charset.StandardCharsets
import java.util.Base64

import org.scalacheck.Gen
import org.scalacheck.Prop._

import munit.ScalaCheckSuite

class ClientAuthSpec extends ScalaCheckSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val id: ClientId = unsafe(ClientId.from("client-1"))

  private val otherId: ClientId = unsafe(ClientId.from("client-2"))

  private val secret: ClientSecret = unsafe(ClientSecret.from("s3cret"))

  private val credentials: ClientCredentials = ClientCredentials(id, secret)

  private def basic(id: String, secret: String): String =
    Base64.getEncoder.encodeToString(s"$id:$secret".getBytes(StandardCharsets.UTF_8))

  private val header: String = s"Basic ${basic("client-1", "s3cret")}"

  test("method parses every registered value") {
    assertEquals(ClientAuthMethod.from("none"), Right(ClientAuthMethod.None))
    assertEquals(ClientAuthMethod.from("client_secret_basic"), Right(ClientAuthMethod.ClientSecretBasic))
    assertEquals(ClientAuthMethod.from("client_secret_post"), Right(ClientAuthMethod.ClientSecretPost))
  }

  test("method refuses an unregistered value") {
    assert(ClientAuthMethod.from("private_key_jwt").isLeft)
  }

  test("input reads basic credentials from the authorization header") {
    val input = ClientAuthInput.from(Some(header), Map.empty)
    assertEquals(input.toOption.flatMap(_.basic), Some(credentials))
  }

  test("input reads a percent encoded basic secret") {
    val encoded = s"Basic ${Base64.getEncoder.encodeToString("client-1:s3cr%3At".getBytes(StandardCharsets.UTF_8))}"
    assertEquals(
      ClientAuthInput.from(Some(encoded), Map.empty).toOption.flatMap(_.basic.map(_.secret.value)),
      Some("s3cr:t")
    )
  }

  test("input ignores an authorization header of another scheme") {
    assertEquals(ClientAuthInput.from(Some("Bearer at-1"), Map.empty).toOption.flatMap(_.basic), None)
  }

  test("input reads the client id and the secret from the body") {
    val input = ClientAuthInput.from(None, Map("client_id" -> "client-1", "client_secret" -> "s3cret"))
    assertEquals(input.toOption.flatMap(_.clientId), Some(id))
    assertEquals(input.toOption.flatMap(_.clientSecret), Some(secret))
  }

  test("input takes the client id from the basic credentials first") {
    val input = ClientAuthInput.from(Some(header), Map("client_id" -> "client-2"))
    assertEquals(input.toOption.flatMap(_.subject), Some(id))
  }

  test("input takes the client id from the body when there is no header") {
    assertEquals(ClientAuthInput.from(None, Map("client_id" -> "client-2")).toOption.map(_.subject), Some(Some(otherId)))
  }

  test("input has no subject without credentials and without a body client id") {
    assertEquals(ClientAuthInput.from(None, Map.empty).toOption.map(_.subject), Some(None))
  }

  test("input refuses a malformed basic header as invalid_client") {
    val input = ClientAuthInput.from(Some("Basic not-base64"), Map.empty)
    assert(input.fold(_.forall(_.description.isEmpty), _ => false))
  }

  test("input refuses a basic header without a separator") {
    val encoded = Base64.getEncoder.encodeToString("client-1".getBytes(StandardCharsets.UTF_8))
    assert(ClientAuthInput.from(Some(s"Basic $encoded"), Map.empty).isInvalid)
  }

  property("client auth method wire round trips") {
    forAll(Gen.oneOf(ClientAuthMethod.all)) { method =>
      Wire[ClientAuthMethod].decode(Wire[ClientAuthMethod].encode(method)) == Right(method)
    }
  }

  property("client auth method wire decoding refuses an unregistered value") {
    forAll(Gen.alphaLowerStr) { raw =>
      !ClientAuthMethod.all.exists(_.value == raw) ==> Wire[ClientAuthMethod].decode(raw).isLeft
    }
  }
}
