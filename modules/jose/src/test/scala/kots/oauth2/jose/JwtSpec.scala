package kots.oauth2.jose

import java.time.Instant
import java.util.Base64

import kots.oauth2.core.Audience
import kots.oauth2.core.ClientId
import kots.oauth2.core.Issuer
import kots.oauth2.core.JwtId
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import munit.FunSuite

class JwtSpec extends FunSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[kots.oauth2.core.ParseFailure, A]): A = Fakes.unsafe(parsed)

  private val published: Jwks = Jwks(List(Fakes.signingJwk))

  private val claims: JwtClaims = JwtClaims(
    issuer = unsafe(Issuer.from("https://server.example")),
    subject = unsafe(Subject.from("user-1")),
    audience = List(unsafe(Audience.from("https://api.example"))),
    clientId = unsafe(ClientId.from("client-1")),
    scopes = unsafe(Scopes.parse("read write")),
    issuedAt = Start,
    expiresAt = Start.plusSeconds(3600L),
    tokenId = unsafe(JwtId.from("jwt-1"))
  )

  test("an issued access token verifies and round trips its claims") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    assertEquals(Jwt.claims(compact, published, Start), Right(claims))
  }

  test("the access token header carries the at jwt type") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    val header = new String(Base64.getUrlDecoder.decode(compact.split('.')(0)), "UTF-8")
    val cursor = io.circe.parser.parse(header).toOption.get.hcursor
    assertEquals(cursor.get[String]("typ").toOption, Some("at+jwt"))
  }

  test("an expired access token is refused") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    assert(Jwt.claims(compact, published, Start.plusSeconds(3600L)).isLeft)
    assert(Jwt.claims(compact, published, Start.plusSeconds(3599L)).isRight)
  }

  test("a token without an audience or scopes omits the claims") {
    val bare = claims.copy(audience = Nil, scopes = Scopes.empty)
    val compact = Jwt.issue(Fakes.signingKey, bare).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    val cursor = io.circe.parser.parse(payload).toOption.get.hcursor
    assertEquals(cursor.keys.map(_.toSet), Some(Set("iss", "sub", "client_id", "jti", "iat", "exp")))
    assertEquals(Jwt.claims(compact, published, Start), Right(bare))
  }

  test("a token with an acr claim round trips it") {
    val stepped = claims.copy(acr = Some(unsafe(kots.oauth2.core.Acr.from("gold"))))
    val compact = Jwt.issue(Fakes.signingKey, stepped).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    val cursor = io.circe.parser.parse(payload).toOption.get.hcursor
    assertEquals(cursor.get[String]("acr").toOption, Some("gold"))
    assertEquals(Jwt.claims(compact, published, Start), Right(stepped))
  }

  test("a token with a notBefore claim renders and round trips it") {
    val stepped = claims.copy(notBefore = Some(Start.plusSeconds(120L)))
    val compact = Jwt.issue(Fakes.signingKey, stepped).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    val cursor = io.circe.parser.parse(payload).toOption.get.hcursor
    assertEquals(cursor.get[Long]("nbf").toOption, Some(Start.plusSeconds(120L).getEpochSecond))
    assertEquals(Jwt.claims(compact, published, Start.plusSeconds(200L)), Right(stepped))
  }

  test("a token that is not yet valid is refused and accepted at its notBefore") {
    val stepped = claims.copy(notBefore = Some(Start.plusSeconds(120L)))
    val compact = Jwt.issue(Fakes.signingKey, stepped).toOption.get
    assert(Jwt.claims(compact, published, Start).isLeft)
    assertEquals(Jwt.claims(compact, published, Start.plusSeconds(120L)), Right(stepped))
  }

  test("an expired token is refused within a bounded skew only") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    val later = Start.plusSeconds(3600L)
    assert(Jwt.claims(compact, published, later).isLeft)
    assertEquals(
      Jwt.claims(compact, published, later, Set(Jwt.AccessTokenType), java.time.Duration.ofSeconds(60L)),
      Right(claims)
    )
  }

  test("a not yet valid token within the bounded skew is accepted") {
    val stepped = claims.copy(notBefore = Some(Start.plusSeconds(120L)))
    val compact = Jwt.issue(Fakes.signingKey, stepped).toOption.get
    assert(Jwt.claims(compact, published, Start).isLeft)
    assertEquals(
      Jwt.claims(compact, published, Start, Set(Jwt.AccessTokenType), java.time.Duration.ofSeconds(120L)),
      Right(stepped)
    )
  }

  test("a token issued in the future is refused within a bounded skew only") {
    val future = claims.copy(issuedAt = Start.plusSeconds(120L))
    val compact = Jwt.issue(Fakes.signingKey, future).toOption.get
    assert(Jwt.claims(compact, published, Start).isLeft)
    assertEquals(
      Jwt.claims(compact, published, Start, Set(Jwt.AccessTokenType), java.time.Duration.ofSeconds(120L)),
      Right(future)
    )
  }

  test("an identity assertion round trips its claims and type") {
    val compact = Jws
      .sign(
        Alg.RS256,
        Fakes.keyId("key-1"),
        Fakes.signingPair.getPrivate,
        Jwt.render(claims),
        Jwt.IdentityAssertionTyp
      )
      .toOption
      .get
    assertEquals(
      Jwt.claims(compact, published, Start, Set(Jwt.IdentityAssertionTyp)),
      Right(claims)
    )
  }

  test("a key bound token round trips the confirmation thumbprint") {
    val bound = claims.copy(jkt = Dpop.thumbprint(Fakes.signingJwk).toOption)
    val compact = Jwt.issue(Fakes.signingKey, bound).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    val cursor = io.circe.parser.parse(payload).toOption.get.hcursor
    assertEquals(cursor.downField("cnf").get[String]("jkt").toOption, bound.jkt.map(_.value))
    assertEquals(Jwt.claims(compact, published, Start), Right(bound))
  }

  test("a certificate bound token round trips the certificate confirmation") {
    val thumbprint = kots.oauth2.core.CertificateThumbprint.from(Fakes.ClientCertificateThumbprint)
    val bound = claims.copy(x5t = thumbprint.toOption)
    val compact = Jwt.issue(Fakes.signingKey, bound).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    val cursor = io.circe.parser.parse(payload).toOption.get.hcursor
    assertEquals(
      cursor.downField("cnf").get[String](Jwt.CertificateConfirmation).toOption,
      Some(Fakes.ClientCertificateThumbprint)
    )
    assertEquals(Jwt.claims(compact, published, Start), Right(bound))
  }

  test("a token bound to a key and a certificate renders both confirmations") {
    val bound = claims.copy(
      jkt = Dpop.thumbprint(Fakes.signingJwk).toOption,
      x5t = kots.oauth2.core.CertificateThumbprint.from(Fakes.ClientCertificateThumbprint).toOption
    )
    val compact = Jwt.issue(Fakes.signingKey, bound).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    val cursor = io.circe.parser.parse(payload).toOption.get.hcursor
    assertEquals(cursor.downField("cnf").keys.map(_.toSet), Some(Set("jkt", Jwt.CertificateConfirmation)))
    assertEquals(Jwt.claims(compact, published, Start), Right(bound))
  }

  test("a token naming its client by azp is read like client_id") {
    val payload = io.circe.Json
      .obj(
        "iss" -> io.circe.Json.fromString("https://server.example"),
        "sub" -> io.circe.Json.fromString("user-1"),
        "azp" -> io.circe.Json.fromString("client-1"),
        "jti" -> io.circe.Json.fromString("jwt-1"),
        "iat" -> io.circe.Json.fromLong(Start.getEpochSecond),
        "exp" -> io.circe.Json.fromLong(Start.plusSeconds(3600L).getEpochSecond)
      )
      .noSpaces
    val compact = Jws
      .sign(Alg.RS256, Fakes.keyId("key-1"), Fakes.signingPair.getPrivate, payload, Jwt.AccessTokenType)
      .toOption
      .get
    val parsed = Jwt.claims(compact, published, Start).toOption.get
    assertEquals(parsed.clientId.value, "client-1")
  }

  test("a plain jwt type is refused by default and read only when allowed") {
    val compact = Jws
      .sign(Alg.RS256, Fakes.keyId("key-1"), Fakes.signingPair.getPrivate, Jwt.render(claims), "JWT")
      .toOption
      .get
    assert(Jwt.claims(compact, published, Start).isLeft)
    assertEquals(
      Jwt.claims(compact, published, Start, Set(Jwt.AccessTokenType, "JWT")),
      Right(claims)
    )
  }

  test("a jws of another type is not an access token") {
    val compact = Jws
      .sign(Alg.RS256, Fakes.keyId("key-1"), Fakes.signingPair.getPrivate, """{"sub":"user-1"}""")
      .toOption
      .get
    assert(Jwt.claims(compact, published, Start).isLeft)
  }

  test("an access token signed by an unpublished key is refused") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    assert(Jwt.claims(compact, Jwks(List(Fakes.rsa("key-1"))), Start).isLeft)
  }

  test("a token with several audiences renders and reads them as an array") {
    val many = claims.copy(
      audience = List(
        unsafe(Audience.from("https://api.example")),
        unsafe(Audience.from("https://other.example"))
      )
    )
    val compact = Jwt.issue(Fakes.signingKey, many).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    val cursor = io.circe.parser.parse(payload).toOption.get.hcursor
    assertEquals(
      cursor.get[List[String]]("aud").toOption,
      Some(List("https://api.example", "https://other.example"))
    )
    assertEquals(Jwt.claims(compact, published, Start), Right(many))
  }

  test("authorization details round trip through the claims") {
    val detailed = claims.copy(
      details = kots.oauth2.core.AuthorizationDetails.of(
        List(
          kots.oauth2.core.AuthorizationDetail.of(
            unsafe(kots.oauth2.core.AuthorizationDetailType.from("account")),
            List(unsafe(kots.oauth2.core.Location.from("https://api.example"))),
            List(unsafe(kots.oauth2.core.Action.from("read"))),
            Map("identifier" -> "1")
          )
        )
      )
    )
    val compact = Jwt.issue(Fakes.signingKey, detailed).toOption.get
    assertEquals(Jwt.claims(compact, published, Start), Right(detailed))
  }

  test("a claim set without authorization details omits them") {
    val compact = Jwt.issue(Fakes.signingKey, claims).toOption.get
    val payload = new String(Base64.getUrlDecoder.decode(compact.split('.')(1)), "UTF-8")
    assert(!payload.contains("authorization_details"))
  }
}
