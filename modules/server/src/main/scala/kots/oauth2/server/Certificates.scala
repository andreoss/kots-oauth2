package kots.oauth2.server

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

import javax.security.auth.x500.X500Principal

import kots.oauth2.core.CertificateSubject
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientCertificate
import kots.oauth2.core.ParseFailure

object Certificates {

  def parse(header: String): Either[ParseFailure, ClientCertificate] =
    for {
      pem <- decoded(header)
      certificate <- x509(pem)
      subject <- CertificateSubject.from(
        certificate.getSubjectX500Principal.getName(X500Principal.RFC2253)
      )
      thumbprint <- CertificateThumbprint.from(digest(certificate))
    } yield ClientCertificate(subject, thumbprint)

  private def decoded(header: String): Either[ParseFailure, String] =
    try Right(java.net.URLDecoder.decode(header, StandardCharsets.UTF_8.name))
    catch {
      case _: IllegalArgumentException => Left(ParseFailure("ClientCertificate", "not percent encoded"))
    }

  private def x509(pem: String): Either[ParseFailure, X509Certificate] =
    try
      CertificateFactory
        .getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))) match {
        case certificate: X509Certificate => Right(certificate)
        case _ => Left(ParseFailure("ClientCertificate", "not an x509 certificate"))
      }
    catch {
      case _: CertificateException => Left(ParseFailure("ClientCertificate", "not a certificate"))
    }

  private def digest(certificate: X509Certificate): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(
      MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded)
    )
}
