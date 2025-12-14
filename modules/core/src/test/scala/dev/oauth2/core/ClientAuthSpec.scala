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

  test("method parses every registered value") {
    assertEquals(ClientAuthMethod.from("none"), Right(ClientAuthMethod.None))
    assertEquals(ClientAuthMethod.from("client_secret_basic"), Right(ClientAuthMethod.ClientSecretBasic))
    assertEquals(ClientAuthMethod.from("client_secret_post"), Right(ClientAuthMethod.ClientSecretPost))
    assertEquals(ClientAuthMethod.from("private_key_jwt"), Right(ClientAuthMethod.PrivateKeyJwt))
    assertEquals(ClientAuthMethod.from("client_secret_jwt"), Right(ClientAuthMethod.ClientSecretJwt))
  }

  test("method refuses an unregistered value") {
    assert(ClientAuthMethod.from("tls_client_auth").isLeft)
  }

  test("input carries a client assertion of the jwt bearer type") {
    val decoded = ClientAuthInput.from(
      None,
      Map("client_assertion" -> "a.b.c", "client_assertion_type" -> ClientAssertion.Type)
    )
    assertEquals(decoded.toOption.flatMap(_.assertion).map(_.value), Some("a.b.c"))
  }

  test("input refuses a client assertion without its type or of another type") {
    assert(ClientAuthInput.from(None, Map("client_assertion" -> "a.b.c")).isInvalid)
    assert(
      ClientAuthInput
        .from(None, Map("client_assertion" -> "a.b.c", "client_assertion_type" -> "urn:other"))
        .isInvalid
    )
    assert(ClientAuthInput.from(None, Map("client_assertion_type" -> ClientAssertion.Type)).isInvalid)
  }

  test("input reads basic credentials from a basic header value") {
    val encoded = Base64.getEncoder.encodeToString("client-1:s3cret".getBytes(StandardCharsets.UTF_8))
    assertEquals(ClientAuthInput.from(Some(encoded), Map.empty).toOption.flatMap(_.basic), Some(credentials))
  }

  test("input reads a percent encoded basic secret") {
    val encoded = Base64.getEncoder.encodeToString("client-1:s3cr%3At".getBytes(StandardCharsets.UTF_8))
    assertEquals(
      ClientAuthInput.from(Some(encoded), Map.empty).toOption.flatMap(_.basic.map(_.secret.value)),
      Some("s3cr:t")
    )
  }

  test("input refuses a malformed basic value as invalid_client") {
    val input = ClientAuthInput.from(Some("not base64 !"), Map.empty)
    assert(input.fold(_.forall(_.description.isEmpty), _ => false))
  }

  test("input refuses a basic value without a separator") {
    val encoded = Base64.getEncoder.encodeToString("client-1".getBytes(StandardCharsets.UTF_8))
    assert(ClientAuthInput.from(Some(encoded), Map.empty).isInvalid)
  }

  test("input reads the client id and the secret from the body") {
    val input = ClientAuthInput.from(None, Map("client_id" -> "client-1", "client_secret" -> "s3cret"))
    assertEquals(input.toOption.flatMap(_.clientId), Some(id))
    assertEquals(input.toOption.flatMap(_.clientSecret), Some(secret))
  }

  test("input takes the client id from the basic credentials first") {
    val encoded = Base64.getEncoder.encodeToString("client-1:s3cret".getBytes(StandardCharsets.UTF_8))
    val input = ClientAuthInput.from(Some(encoded), Map("client_id" -> "client-2"))
    assertEquals(input.toOption.flatMap(_.subject), Some(id))
  }

  test("input takes the client id from the body when there are no credentials") {
    assertEquals(ClientAuthInput.from(None, Map("client_id" -> "client-2")).toOption.map(_.subject), Some(Some(otherId)))
  }

  test("input has no subject without credentials and without a body client id") {
    assertEquals(ClientAuthInput.from(None, Map.empty).toOption.map(_.subject), Some(None))
  }

  test("input refuses a body client id that does not parse as invalid_client") {
    val input = ClientAuthInput.from(None, Map("client_id" -> "has space"))
    assert(input.fold(_.forall(_.description.isEmpty), _ => false))
  }

  test("input refuses a body secret that does not parse as invalid_client") {
    assert(ClientAuthInput.from(None, Map("client_secret" -> "has space")).isInvalid)
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
