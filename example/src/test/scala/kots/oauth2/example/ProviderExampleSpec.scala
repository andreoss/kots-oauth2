package kots.oauth2.example

import munit.FunSuite

class ProviderExampleSpec extends FunSuite {

  test("a provider document yields its issuer, token endpoint and key set uri") {
    val text =
      """{"issuer":"https://provider.example","token_endpoint":"https://provider.example/token",""" +
        """"jwks_uri":"https://provider.example/jwks"}"""
    val document = ProviderExample.document(text).toOption.get
    assertEquals(document.issuer, "https://provider.example")
    assertEquals(document.tokenEndpoint.value, "https://provider.example/token")
    assertEquals(document.jwksUri.map(_.value), Some("https://provider.example/jwks"))
    val bare =
      """{"issuer":"https://provider.example","token_endpoint":"https://provider.example/token"}"""
    assertEquals(ProviderExample.document(bare).toOption.get.jwksUri, None)
  }

  test("a document without the endpoint or unreadable json is refused") {
    assert(ProviderExample.document("""{"issuer":"https://provider.example"}""").isLeft)
    assert(ProviderExample.document("not json").isLeft)
    assert(ProviderExample.document("""{"issuer":"x","token_endpoint":"relative"}""").isLeft)
  }
}
