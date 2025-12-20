package kots.oauth2.jose

import kots.oauth2.core.KeyId
import kots.oauth2.core.ParseFailure

object Fakes {

  def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(failure => sys.error(failure.toString), identity)

  val Modulus: String =
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

  val Exponent: String = "AQAB"

  val X: String = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"

  val Y: String = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

  def keyId(value: String): KeyId = unsafe(KeyId.from(value))

  lazy val signingPair: java.security.KeyPair = {
    val generator = java.security.KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator.generateKeyPair
  }

  lazy val signingJwk: Jwk = {
    val public = signingPair.getPublic.asInstanceOf[java.security.interfaces.RSAPublicKey]
    def parameter(value: java.math.BigInteger): String =
      java.util.Base64.getUrlEncoder.withoutPadding.encodeToString(value.toByteArray.dropWhile(_ == 0))
    unsafe(
      Jwk.rsa(keyId("key-1"), Alg.RS256, parameter(public.getModulus), parameter(public.getPublicExponent))
    )
  }

  lazy val signingKey: SigningKey = SigningKey(keyId("key-1"), Alg.RS256, signingPair.getPrivate)

  val ClientCertificateSubject: String = "CN=client-1"

  val ClientCertificateThumbprint: String = "BemrEoEAcUobpCSYeBpZzeHt_OVDWYeWZSLeb4Y914o"

  val OtherCertificateThumbprint: String = "MYymgvoHqZzqLq_2fC-g4YNBCFW289GAtVi1bkgdRaE"

  val ClientCertificatePem: String =
    """-----BEGIN CERTIFICATE-----
      |MIICojCCAYoCCQCiseTxSFY9zDANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhj
      |bGllbnQtMTAeFw0yNjA5MTEwMTIzMzVaFw0zNjA5MDgwMTIzMzVaMBMxETAPBgNV
      |BAMMCGNsaWVudC0xMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8RG4
      |n8jfkPf5a7od54HJabXN3UTBKtl5lU/XiMlQfauW454CtpDTOjEcI0bR36UhgiYJ
      |06z/GxAYYj5CTN7ZT24JomLKQkUuCIU2lGUfH9gFstErBXzwTK1UVuLBj0LbK6N/
      |9GYdNmZlHtQFChgYBUtd7ggecORj4Ub2T5a28jrjIaxWKAlLwjrtCjRN7LrSlxzV
      |tMPxWa0h10G/Lr8U5/vIeN2KLQ+ym9U4sNJ+KKvhl0sQfA1tQwqav6Ww9lkoM7H2
      |fOTRdEFziOS/Xp/nRJQTibM0gd2n7JFvO9Rr7+XQt5SN2Kndbr+BbgeHLQXC/tfH
      |1D8mp5wDyJMqAa8p3wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB1LRsmoOG4+ReU
      |UUzzZE+/LKe3HJDLEkl2O92E10Et5zQkEKOGnsumnuHz2Pv3LvHFRQ0b0GsOY5J2
      |lE6G+kszTpuS7kpKW/YlptrDp5zpRGvz0oKYyhP6Ft0cqG48QBLH33a7gSfhgU8b
      |DcYpn1/xUwQKKW2+/Uh/lNBbyBq9/1C/uDqHqxOS3ZO3HQ/fxOpfAsNa48lMRjNx
      |3ydGqSw57RfNSNKLG0bdfmjXdEHb6P87ZCcHuUmOx+438QT90eo9AaYaHGE1eY+S
      |vZRI91O9gO8v5m8FGLg5XOQlG5AoDd8C5vohK50E0Z2GKA4ptfwfPmlmwZRiDubo
      |Bz1HueJu
      |-----END CERTIFICATE-----""".stripMargin

  val OtherCertificatePem: String =
    """-----BEGIN CERTIFICATE-----
      |MIICoDCCAYgCCQCzDvlmy81xizANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdv
      |dGhlci0xMB4XDTI2MDkxMTAxMjM0MVoXDTM2MDkwODAxMjM0MVowEjEQMA4GA1UE
      |AwwHb3RoZXItMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXeCayo
      |QEPD3z7JgCbGwzOYDmy0dAhG6mZoJkRlThZ1+VTKNLE7Z6KMnekyfZ8PtVYeeRUT
      |SBc1z7ZfsuJW7QpsLPrqy7bgnAkXgyHxgPVg939b6/6BAq68S8yasYNlmj1Kz+oD
      |rm+6Su3o4awt82NSPRQJ4T3tP8HgIV1fDP1ab+9BZ5625G1yjoGq3i4LXI7yas73
      |FdRXHUBdCA/m+UZWUv9hkdiuMcw93hs/GHy0nEp4jiQdEogCwjW8cJmCJW62Jv+K
      |jUDdCGV4NzdSCAavk9anS9MttjVcse33B/tVGqHZKchjQbjaq4zX/37PUv9Aj3/I
      |h9JjSVFVFU/SqjMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAMLqLJJZeHd6/QMKA
      |3ucXRwSyTc9DL7yRMXF3w8RDp29uxbxncFjwFe50AM5Naqu0KWVafiokTCOneLq1
      |+TEyv2SbHc4nC4ol885sHYIRcVlgDwTTggg0fWq1w/bLxadDFpjAzrzjXB6IxgHO
      |yNEjAQymQb/7kmkSe1ggHAMEuHy0K2l+qXLjuQNkMbBQ6ksquvlP8+mmCjqY7qha
      |QmyUsP2+ymE9x34WXsXbhXUx+B0/9D16TV9uxGhbk5aTNXAqDrqnwa1dSHYGi1nY
      |bdh21Yq/52g0BfPW3hNjJQ1Bm/SwdHoADY7iUfGG3BKqNga1FkSaJGxnUB7j/iSk
      |fDuR4w==
      |-----END CERTIFICATE-----""".stripMargin

  def rsa(kid: String): Jwk = unsafe(Jwk.rsa(keyId(kid), Alg.RS256, Modulus, Exponent))

  def ec(kid: String): Jwk = unsafe(Jwk.ec(keyId(kid), Alg.ES256, "P-256", X, Y))

  def okp(kid: String): Jwk = unsafe(Jwk.okp(keyId(kid), Alg.EdDSA, "Ed25519", X))
}
