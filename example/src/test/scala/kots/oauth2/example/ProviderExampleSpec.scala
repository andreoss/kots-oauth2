package kots.oauth2.example

import munit.FunSuite

class ProviderExampleSpec extends FunSuite {

  test("a provider document yields its issuer and token endpoint") {
    val text =
      """{"issuer":"https://provider.example","token_endpoint":"https://provider.example/token"}"""
    val document = ProviderExample.document(text).toOption.get
    assertEquals(document.issuer, "https://provider.example")
    assertEquals(document.tokenEndpoint.value, "https://provider.example/token")
  }

  test("a document without the endpoint or unreadable json is refused") {
    assert(ProviderExample.document("""{"issuer":"https://provider.example"}""").isLeft)
    assert(ProviderExample.document("not json").isLeft)
    assert(ProviderExample.document("""{"issuer":"x","token_endpoint":"relative"}""").isLeft)
  }
}
