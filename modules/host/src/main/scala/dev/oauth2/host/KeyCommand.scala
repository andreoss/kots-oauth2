package dev.oauth2.host

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

import cats.effect.kernel.Sync
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.Entropy
import dev.oauth2.core.KeyId
import dev.oauth2.core.ParseFailure
import dev.oauth2.jose.Alg
import dev.oauth2.jose.Jwk
import dev.oauth2.store.KeyStore

final class KeyCommand[F[_]: Sync](store: KeyStore[F], entropy: Entropy[F]) {

  def generate: F[Either[ParseFailure, KeyCommand.Generated]] =
    for {
      raw <- entropy.bytes(KeyCommand.KidBytes)
      pair <- Sync[F].delay {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(KeyCommand.KeyBits)
        generator.generateKeyPair
      }
      minted = KeyCommand.published(Entropy.hex(raw), pair)
      _ <- minted.fold(_ => Sync[F].unit, generated => store.add(generated.jwk))
    } yield minted

  def rotate: F[Either[ParseFailure, KeyCommand.Rotated]] =
    store.current.flatMap { previous =>
      previous.fold(Sync[F].unit)(key => store.retire(key.kid)) >>
        generate.map(_.map(KeyCommand.Rotated(previous.map(_.kid), _)))
    }
}

object KeyCommand {

  val KeyBits: Int = 2048

  val KidBytes: Int = 8

  final case class Generated(jwk: Jwk, privateKey: PrivateKey)

  final case class Rotated(retired: Option[KeyId], generated: Generated)

  def pem(key: PrivateKey): String = {
    val body = Base64.getMimeEncoder(64, "\n".getBytes("US-ASCII")).encodeToString(key.getEncoded)
    s"-----BEGIN PRIVATE KEY-----\n$body\n-----END PRIVATE KEY-----"
  }

  private def published(seed: String, pair: KeyPair): Either[ParseFailure, Generated] = {
    val public = pair.getPublic.asInstanceOf[RSAPublicKey]
    def parameter(value: java.math.BigInteger): String = {
      val raw = value.toByteArray.dropWhile(_ == 0.toByte)
      Base64.getUrlEncoder.withoutPadding.encodeToString(raw)
    }
    for {
      kid <- KeyId.from(seed)
      jwk <- Jwk.rsa(kid, Alg.RS256, parameter(public.getModulus), parameter(public.getPublicExponent))
    } yield Generated(jwk, pair.getPrivate)
  }
}
