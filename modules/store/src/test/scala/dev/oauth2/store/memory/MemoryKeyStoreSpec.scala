package dev.oauth2.store.memory

import cats.effect.IO
import dev.oauth2.core.KeyId
import dev.oauth2.jose.Fakes
import dev.oauth2.jose.Jwk
import dev.oauth2.jose.Jwks
import munit.CatsEffectSuite

class MemoryKeyStoreSpec extends CatsEffectSuite {

  private val first: KeyId = Fakes.keyId("key-1")

  private val second: KeyId = Fakes.keyId("key-2")

  private val firstKey: Jwk = Fakes.rsa("key-1")

  private val secondKey: Jwk = Fakes.ec("key-2")

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
