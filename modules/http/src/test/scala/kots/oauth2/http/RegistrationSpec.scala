package kots.oauth2.http

import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ParseFailure
import io.circe.Json
import munit.FunSuite

class RegistrationSpec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private def body(fields: (String, Json)*): Map[String, Json] = Map(fields: _*)

  private val uris: Json = Json.arr(Json.fromString("https://client.example/cb"))

  test("a registration parses its redirect uris, method and scope") {
    val parsed = Registration
      .parse(
        body(
          "redirect_uris" -> uris,
          "token_endpoint_auth_method" -> Json.fromString("client_secret_post"),
          "scope" -> Json.fromString("read write")
        )
      )
      .toOption
      .get
    assertEquals(parsed.redirectUris.map(_.value), Set("https://client.example/cb"))
    assertEquals(parsed.authMethod, ClientAuthMethod.ClientSecretPost)
    assertEquals(parsed.scopes.value.map(_.value), Set("read", "write"))
  }

  test("a registration defaults to basic authentication and no scope") {
    val parsed = Registration.parse(body("redirect_uris" -> uris)).toOption.get
    assertEquals(parsed.authMethod, ClientAuthMethod.ClientSecretBasic)
    assertEquals(parsed.scopes.value, Set.empty[kots.oauth2.core.Scope])
  }

  test("a registration without a valid redirect uri is refused") {
    assertEquals(
      Registration.parse(body()).left.toOption.map(_.code),
      Some("invalid_redirect_uri")
    )
    assertEquals(
      Registration
        .parse(body("redirect_uris" -> Json.arr(Json.fromString("https://client.example/*"))))
        .left
        .toOption
        .map(_.code),
      Some("invalid_redirect_uri")
    )
    assertEquals(
      Registration.parse(body("redirect_uris" -> Json.arr())).left.toOption.map(_.code),
      Some("invalid_redirect_uri")
    )
  }

  test("a registration with unusable metadata is refused") {
    assertEquals(
      Registration
        .parse(
          body("redirect_uris" -> uris, "token_endpoint_auth_method" -> Json.fromString("private_key_jwt"))
        )
        .left
        .toOption
        .map(_.code),
      Some("invalid_client_metadata")
    )
    assertEquals(
      Registration
        .parse(body("redirect_uris" -> uris, "scope" -> Json.fromString("read  write")))
        .left
        .toOption
        .map(_.code),
      Some("invalid_client_metadata")
    )
  }

  test("a registration response renders the issued credentials and metadata") {
    val parsed =
      Registration.parse(body("redirect_uris" -> uris, "scope" -> Json.fromString("read"))).toOption.get
    val rendered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(
        unsafe(kots.oauth2.core.ClientId.from("client-9")),
        Some(unsafe(ClientSecret.from("s3cret-9"))),
        parsed
      )
    )
    assertEquals(rendered("client_id"), Json.fromString("client-9"))
    assertEquals(rendered("client_secret"), Json.fromString("s3cret-9"))
    assertEquals(rendered("token_endpoint_auth_method"), Json.fromString("client_secret_basic"))
    assertEquals(rendered("redirect_uris"), uris)
    assertEquals(rendered("scope"), Json.fromString("read"))
  }

  test("a public registration response carries no secret") {
    val parsed = Registration
      .parse(body("redirect_uris" -> uris, "token_endpoint_auth_method" -> Json.fromString("none")))
      .toOption
      .get
    val rendered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(unsafe(kots.oauth2.core.ClientId.from("client-9")), None, parsed)
    )
    assert(!rendered.contains("client_secret"))
  }
}
