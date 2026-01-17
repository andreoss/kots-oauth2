package dev.oauth2.host

import cats.effect.IO

import dev.oauth2.core.Entropy
import dev.oauth2.jose.Jws
import dev.oauth2.store.memory.InMemoryKeyStore
import munit.CatsEffectSuite

class KeyCommandSpec extends CatsEffectSuite {

  private val entropy: Entropy[IO] = {
    var calls = 0
    new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO {
        calls += 1
        Array.fill(n)(calls.toByte)
      }
    }
  }

  private def setup: IO[(KeyCommand[IO], InMemoryKeyStore[IO])] =
    InMemoryKeyStore.create[IO].map(store => (new KeyCommand[IO](store, entropy), store))

  test("a generated key signs tokens that verify against the published set") {
    for {
      pair <- setup
      (command, store) = pair
      generated <- command.generate
      published <- store.jwks
      current <- store.current
    } yield {
      val minted = generated.toOption.get
      assertEquals(current.map(_.kid), Some(minted.jwk.kid))
      val compact = Jws
        .sign(minted.jwk.alg, minted.jwk.kid, minted.privateKey, """{"sub":"user-1"}""")
        .toOption
        .get
      assertEquals(Jws.verify(compact, published).toOption, Some("""{"sub":"user-1"}"""))
    }
  }

  test("a rotation retires the current key and mints a successor") {
    for {
      pair <- setup
      (command, store) = pair
      first <- command.generate
      rotated <- command.rotate
      published <- store.jwks
      current <- store.current
    } yield {
      val outcome = rotated.toOption.get
      assertEquals(outcome.retired, Some(first.toOption.get.jwk.kid))
      assertEquals(current.map(_.kid), Some(outcome.generated.jwk.kid))
      assertEquals(published.keys.map(_.kid).toSet.size, 2)
    }
  }

  test("every generated key draws a distinct identifier") {
    for {
      pair <- setup
      (command, _) = pair
      first <- command.generate
      second <- command.generate
    } yield assert(first.toOption.get.jwk.kid != second.toOption.get.jwk.kid)
  }

  test("the private key renders as a pkcs8 pem") {
    for {
      pair <- setup
      (command, _) = pair
      generated <- command.generate
    } yield {
      val pem = KeyCommand.pem(generated.toOption.get.privateKey)
      assert(pem.startsWith("-----BEGIN PRIVATE KEY-----"))
      assert(pem.trim.endsWith("-----END PRIVATE KEY-----"))
      val body = pem.linesIterator.filterNot(_.startsWith("-----")).mkString
      assert(java.util.Base64.getDecoder.decode(body).nonEmpty)
    }
  }
}
