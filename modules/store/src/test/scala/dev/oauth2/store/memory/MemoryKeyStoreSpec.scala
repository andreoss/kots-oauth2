package dev.oauth2.store.memory

import cats.effect.IO
import dev.oauth2.core.KeyId
import dev.oauth2.core.ParseFailure
import dev.oauth2.jose.Alg
import dev.oauth2.jose.Jwk
import dev.oauth2.jose.Jwks
import munit.CatsEffectSuite

class MemoryKeyStoreSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val first: KeyId = unsafe(KeyId.from("key-1"))

  private val second: KeyId = unsafe(KeyId.from("key-2"))

  private val n: String = "t6Q8SWSFZkG9s2Y0m1IuA"

  private val e: String = "AQAB"

  private val x: String = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"

  private val y: String = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

  private val firstKey: Jwk = unsafe(Jwk.rsa(first, Alg.RS256, n, e))

  private val secondKey: Jwk = unsafe(Jwk.ec(second, Alg.ES256, "P-256", x, y))

  private def store: IO[InMemoryKeyStore[IO]] =
    InMemoryKeyStore.create[IO].flatMap(keys => keys.add(firstKey).as(keys))

  test("an empty store publishes no key and has no current key") {
    for {
      keys <- InMemoryKeyStore.create[IO]
      published <- keys.jwks
      current <- keys.current
    } yield {
      assertEquals(published, Jwks.empty)
      assertEquals(current, None)
    }
  }

  test("an added key is published and becomes the current key") {
    for {
      keys <- store
      published <- keys.jwks
      current <- keys.current
      found <- keys.find(first)
      absent <- keys.find(second)
    } yield {
      assertEquals(published.keys, List(firstKey))
      assertEquals(current, Some(firstKey))
      assertEquals(found, Some(firstKey))
      assertEquals(absent, None)
    }
  }

  test("a rotated key publishes both keys and moves the current one") {
    for {
      keys <- store
      _ <- keys.add(secondKey)
      published <- keys.jwks
      current <- keys.current
    } yield {
      assertEquals(published.keys, List(firstKey, secondKey))
      assertEquals(current, Some(secondKey))
    }
  }

  test("a retired key stays published and stops being current") {
    for {
      keys <- store
      _ <- keys.add(secondKey)
      _ <- keys.retire(second)
      published <- keys.jwks
      current <- keys.current
      found <- keys.find(second)
    } yield {
      assertEquals(published.keys, List(firstKey, secondKey))
      assertEquals(current, Some(firstKey))
      assertEquals(found, Some(secondKey))
    }
  }

  test("retiring an unknown key changes nothing") {
    for {
      keys <- store
      _ <- keys.retire(second)
      published <- keys.jwks
      current <- keys.current
    } yield {
      assertEquals(published.keys, List(firstKey))
      assertEquals(current, Some(firstKey))
    }
  }

  test("adding a key with a known identifier replaces it") {
    for {
      keys <- store
      _ <- keys.retire(first)
      _ <- keys.add(firstKey)
      published <- keys.jwks
      current <- keys.current
    } yield {
      assertEquals(published.keys, List(firstKey))
      assertEquals(current, Some(firstKey))
    }
  }
}
