package kots.oauth2.store.sql

import java.sql.DriverManager
import java.util.concurrent.atomic.AtomicInteger

import cats.effect.IO
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.RegistrationToken
import kots.oauth2.core.RegistrationTokenHash
import kots.oauth2.core.Scopes
import kots.oauth2.jose.Fakes
import kots.oauth2.jose.Jwks
import kots.oauth2.store.Client
import munit.CatsEffectSuite

class SqlClientStoreSpec extends CatsEffectSuite {

  private val databases = new AtomicInteger(0)

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val id: ClientId = unsafe(ClientId.from("client-1"))

  private val registered: Client = Client(
    id,
    Set(
      unsafe(RedirectUri.from("https://client.example/cb")),
      unsafe(RedirectUri.from("https://client.example/other"))
    ),
    unsafe(Scopes.parse("read write")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret")))),
    keys = Jwks(List(Fakes.rsa("key-1"), Fakes.ec("key-2"))),
    registrationTokenHash =
      Some(RegistrationTokenHash.of(unsafe(RegistrationToken.from("registration-token")))),
    secret = Some(unsafe(ClientSecret.from("s3cret"))),
    certificateThumbprint = Some(unsafe(CertificateThumbprint.from(Fakes.ClientCertificateThumbprint)))
  )

  private def setup: IO[SqlClientStore[IO]] = {
    val name = s"clients-${databases.incrementAndGet()}"
    val connect = IO.blocking {
      Class.forName("org.h2.Driver")
      DriverManager.getConnection(s"jdbc:h2:mem:$name;DB_CLOSE_DELAY=-1")
    }
    SqlClientStore.create[IO](connect).toOption.get
  }

  test("a saved client is found with every field and key intact") {
    for {
      store <- setup
      _ <- store.save(registered)
      found <- store.find(id)
      absent <- store.find(unsafe(ClientId.from("absent")))
    } yield {
      assertEquals(found, Some(registered))
      assertEquals(absent, None)
    }
  }

  test("saving the same client id replaces the registration") {
    for {
      store <- setup
      _ <- store.save(registered)
      _ <- store.save(
        registered.copy(scopes = unsafe(Scopes.parse("read")), keys = Jwks(Nil), secret = None)
      )
      found <- store.find(id)
    } yield {
      assertEquals(found.map(_.scopes), Some(unsafe(Scopes.parse("read"))))
      assertEquals(found.map(_.keys), Some(Jwks(Nil)))
      assertEquals(found.flatMap(_.secret), None)
    }
  }

  test("a deleted client is gone with its keys") {
    for {
      store <- setup
      _ <- store.save(registered)
      _ <- store.delete(id)
      found <- store.find(id)
      _ <- store.delete(unsafe(ClientId.from("absent")))
    } yield assertEquals(found, None)
  }
}
