package kots.oauth2.server

import cats.effect.IO
import munit.CatsEffectSuite

class AssertionIssuersSpec extends CatsEffectSuite {

  private val issuer: kots.oauth2.core.Issuer =
    kots.oauth2.core.Issuer.from("https://idp.example").toOption.get

  private val jwks: kots.oauth2.jose.Jwks =
    kots.oauth2.jose.Jwks(List(kots.oauth2.jose.Fakes.signingJwk))

  test("the static adapter resolves a trusted issuer") {
    val resolved = AssertionIssuers.static[IO](Map(issuer -> jwks)).keys(issuer)
    assertIO(resolved.map(_.contains(jwks)), true)
  }

  test("the static adapter resolves nothing for an untrusted issuer") {
    val untrusted = kots.oauth2.core.Issuer.from("https://untrusted.example").toOption.get
    val resolved = AssertionIssuers.static[IO](Map(issuer -> jwks)).keys(untrusted)
    assertIO(resolved.map(_.isEmpty), true)
  }
}
