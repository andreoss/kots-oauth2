package dev.oauth2.store.memory

import cats.effect.IO
import dev.oauth2.core.ClientId
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Scopes
import dev.oauth2.core.Subject
import dev.oauth2.store.ConsentRecord
import munit.CatsEffectSuite

class MemoryConsentStoreSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val other: Subject = unsafe(Subject.from("user-2"))

  private def scopes(raw: String): Scopes = unsafe(Scopes.parse(raw))

  test("a granted consent covers the scopes it names and nothing more") {
    for {
      consents <- InMemoryConsentStore.create[IO]
      _ <- consents.grant(ConsentRecord(clientId, subject, scopes("read")))
      covered <- consents.decide(clientId, subject, scopes("read"))
      wider <- consents.decide(clientId, subject, scopes("read write"))
      stranger <- consents.decide(clientId, other, scopes("read"))
    } yield {
      assertEquals(covered, true)
      assertEquals(wider, false)
      assertEquals(stranger, false)
    }
  }

  test("a later grant unions with the recorded consent") {
    for {
      consents <- InMemoryConsentStore.create[IO]
      _ <- consents.grant(ConsentRecord(clientId, subject, scopes("read")))
      _ <- consents.grant(ConsentRecord(clientId, subject, scopes("write")))
      covered <- consents.decide(clientId, subject, scopes("read write"))
    } yield assertEquals(covered, true)
  }

  test("an absent consent decides against every request") {
    for {
      consents <- InMemoryConsentStore.create[IO]
      empty <- consents.decide(clientId, subject, Scopes.empty)
      named <- consents.decide(clientId, subject, scopes("read"))
    } yield {
      assertEquals(empty, false)
      assertEquals(named, false)
    }
  }

  test("a revoked consent is gone") {
    for {
      consents <- InMemoryConsentStore.create[IO]
      _ <- consents.grant(ConsentRecord(clientId, subject, scopes("read")))
      _ <- consents.revoke(clientId, subject)
      covered <- consents.decide(clientId, subject, scopes("read"))
    } yield assertEquals(covered, false)
  }
}
