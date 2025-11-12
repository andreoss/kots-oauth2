package dev.oauth2.server

import java.nio.charset.StandardCharsets
import java.util.Base64

import cats.effect.IO

import dev.oauth2.core.ClientAuthInput
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientId
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.Scopes
import dev.oauth2.store.Client
import dev.oauth2.store.memory.InMemoryClientStore

import munit.CatsEffectSuite

class ClientAuthenticationSpec extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val id: ClientId = unsafe(ClientId.from("client-1"))

  private val otherId: ClientId = unsafe(ClientId.from("client-2"))

  private val secret: ClientSecret = unsafe(ClientSecret.from("s3cret"))

  private val storedHash: ClientSecretHash = ClientSecretHash.of(secret)

  private def basic(id: String, secret: String): String =
    s"Basic ${Base64.getEncoder.encodeToString(s"$id:$secret".getBytes(StandardCharsets.UTF_8))}"

  private def client(
      method: ClientAuthMethod = ClientAuthMethod.ClientSecretBasic,
      hash: Option[ClientSecretHash] = Some(storedHash),
      id: ClientId = id
  ): Client =
    Client(id, Set.empty, Scopes.empty, method, hash)

  private def service(clients: List[Client]): IO[ClientAuthentication[IO]] =
    InMemoryClientStore.create[IO](clients).map(store => new RegisteredClientAuthentication[IO](store))

  private def input(
      authorization: Option[String] = None,
      params: Map[String, String] = Map.empty
  ): ClientAuthInput =
    ClientAuthInput.from(authorization, params).toOption.get

  private def rejection(result: Either[OAuth2Error, Client]): OAuth2Error =
    result.left.getOrElse(OAuth2Error.ServerError())

  test("basic credentials authenticate a client registered for client_secret_basic") {
    val registered = client()
    for {
      authentication <- service(List(registered))
      result <- authentication.authenticate(input(Some(basic("client-1", "s3cret"))))
    } yield assertEquals(result, Right(registered))
  }

  test("body credentials authenticate a client registered for client_secret_post") {
    val registered = client(ClientAuthMethod.ClientSecretPost)
    for {
      authentication <- service(List(registered))
      result <- authentication.authenticate(input(None, Map("client_id" -> "client-1", "client_secret" -> "s3cret")))
    } yield assertEquals(result, Right(registered))
  }

  test("basic credentials are refused for a client registered for client_secret_post") {
    for {
      authentication <- service(List(client(ClientAuthMethod.ClientSecretPost)))
      result <- authentication.authenticate(input(Some(basic("client-1", "s3cret"))))
    } yield assert(result.isLeft)
  }

  test("body credentials are refused for a client registered for client_secret_basic") {
    for {
      authentication <- service(List(client()))
      result <- authentication.authenticate(input(None, Map("client_id" -> "client-1", "client_secret" -> "s3cret")))
    } yield assert(result.isLeft)
  }

  test("a wrong secret is refused as invalid_client without a description") {
    for {
      authentication <- service(List(client()))
      result <- authentication.authenticate(input(Some(basic("client-1", "wrong"))))
    } yield {
      assertEquals(rejection(result), OAuth2Error.InvalidClient())
      assertEquals(rejection(result).body, Map("error" -> "invalid_client"))
      assert(rejection(result).challenge.isDefined)
    }
  }

  test("an unknown client is refused") {
    for {
      authentication <- service(List.empty)
      result <- authentication.authenticate(input(Some(basic("client-1", "s3cret"))))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("a confidential client without credentials is refused") {
    for {
      authentication <- service(List(client()))
      result <- authentication.authenticate(input(None, Map("client_id" -> "client-1")))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("a public client authenticates with none") {
    val registered = client(ClientAuthMethod.None, None)
    for {
      authentication <- service(List(registered))
      result <- authentication.authenticate(input(None, Map("client_id" -> "client-1")))
    } yield assertEquals(result, Right(registered))
  }

  test("a public client is not confidential") {
    assertEquals(client(ClientAuthMethod.None, None).confidential, false)
    assertEquals(client().confidential, true)
  }

  test("a public client sending a secret is refused") {
    for {
      authentication <- service(List(client(ClientAuthMethod.None, None)))
      result <- authentication.authenticate(input(None, Map("client_id" -> "client-1", "client_secret" -> "s3cret")))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("basic credentials for another client than the body client id are refused") {
    for {
      authentication <- service(List(client(), client(id = otherId)))
      result <- authentication.authenticate(input(Some(basic("client-1", "s3cret")), Map("client_id" -> "client-2")))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("credentials without a client id are refused") {
    for {
      authentication <- service(List(client()))
      result <- authentication.authenticate(input())
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("a client registered without a secret hash is refused") {
    for {
      authentication <- service(List(client(hash = None)))
      result <- authentication.authenticate(input(Some(basic("client-1", "s3cret"))))
    } yield assertEquals(rejection(result), OAuth2Error.InvalidClient())
  }

  test("every failure answers the same error") {
    val registered = client()
    for {
      authentication <- service(List(registered))
      unknown <- authentication.authenticate(input(Some(basic("client-2", "s3cret"))))
      wrong <- authentication.authenticate(input(Some(basic("client-1", "wrong"))))
      missing <- authentication.authenticate(input(None, Map("client_id" -> "client-1")))
    } yield {
      assertEquals(rejection(unknown), OAuth2Error.InvalidClient())
      assertEquals(rejection(wrong), OAuth2Error.InvalidClient())
      assertEquals(rejection(missing), OAuth2Error.InvalidClient())
    }
  }
}
