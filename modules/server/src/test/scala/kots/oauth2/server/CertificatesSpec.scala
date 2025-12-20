package kots.oauth2.server

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

import kots.oauth2.jose.Fakes
import munit.FunSuite

class CertificatesSpec extends FunSuite {

  private def encoded(pem: String): String =
    URLEncoder.encode(pem, StandardCharsets.UTF_8.name)

  test("a forwarded certificate parses to its subject and thumbprint") {
    val parsed = Certificates.parse(encoded(Fakes.ClientCertificatePem)).toOption.get
    assertEquals(parsed.subject.value, Fakes.ClientCertificateSubject)
    assertEquals(parsed.thumbprint.value, Fakes.ClientCertificateThumbprint)
  }

  test("two certificates carry distinct thumbprints") {
    val first = Certificates.parse(encoded(Fakes.ClientCertificatePem)).toOption.get
    val second = Certificates.parse(encoded(Fakes.OtherCertificatePem)).toOption.get
    assertEquals(second.subject.value, "CN=other-1")
    assertEquals(second.thumbprint.value, Fakes.OtherCertificateThumbprint)
    assert(first.thumbprint != second.thumbprint)
  }

  test("a header that is not percent encoded is refused") {
    assert(Certificates.parse("%zz").isLeft)
  }

  test("a decoded value that is not a certificate is refused") {
    assert(Certificates.parse(encoded("hello")).isLeft)
    assert(Certificates.parse(encoded("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")).isLeft)
  }
}
