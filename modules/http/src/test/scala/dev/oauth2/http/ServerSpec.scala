package dev.oauth2.http

import cats.Id

import dev.oauth2.core.AccessToken
import dev.oauth2.core.OAuth2Error
import dev.oauth2.core.ParseFailure
import dev.oauth2.core.RefreshToken
import dev.oauth2.core.Scopes
import munit.FunSuite
import sttp.monad.IdentityMonad
import sttp.tapir.server.ServerEndpoint

class ServerSpec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val accessToken: AccessToken = unsafe(AccessToken.from("at-1"))

  private val refreshToken: RefreshToken = unsafe(RefreshToken.from("rt-1"))

  private val scopes: Scopes = unsafe(Scopes.parse("openid read"))

  private def success(response: TokenResponse): TokenLogic[Id] =
    new TokenLogic[Id] {
      def apply(authorization: Option[String], parameters: Map[String, String]) = Right(response)
    }

  private def failure(error: OAuth2Error): TokenLogic[Id] =
    new TokenLogic[Id] {
      def apply(authorization: Option[String], parameters: Map[String, String]) = Left(error)
    }

  private type Bound[F[_]] = ServerEndpoint[Any, F] {
    type SECURITY_INPUT = Unit
    type PRINCIPAL = Unit
    type INPUT = (Option[String], Map[String, String])
    type ERROR_OUTPUT = OAuth2Error
    type OUTPUT = Map[String, String]
  }

  private def run(logic: TokenLogic[Id], input: (Option[String], Map[String, String])) =
    Server.token(logic).asInstanceOf[Bound[Id]].logic(IdentityMonad)(())(input)

  test("a token response renders its type, lifetime, scope and refresh token") {
    val rendered = TokenResponse.render(TokenResponse(accessToken, 3600L, scopes, Some(refreshToken)))
    assertEquals(rendered("access_token"), "at-1")
    assertEquals(rendered("token_type"), "Bearer")
    assertEquals(rendered("expires_in"), "3600")
    assertEquals(rendered("scope"), "openid read")
    assertEquals(rendered("refresh_token"), "rt-1")
  }

  test("a token response without a scope or a refresh token renders neither") {
    val rendered = TokenResponse.render(TokenResponse(accessToken, 60L, Scopes.empty, None))
    assertEquals(rendered.keySet, Set("access_token", "token_type", "expires_in"))
  }

  test("the bound logic answers through the described endpoint") {
    val endpoint = Server.token(success(TokenResponse(accessToken, 1L, Scopes.empty, None)))
    assertEquals(endpoint.showPathTemplate(showQueryParam = None), Endpoints.token.showPathTemplate(showQueryParam = None))
    assertEquals(endpoint.method.map(_.method), Endpoints.token.method.map(_.method))
  }

  test("a answered token is rendered as the endpoint body") {
    val out = run(success(TokenResponse(accessToken, 3600L, scopes, None)), (None, Map("grant_type" -> "code")))
    assertEquals(out, Right(Map("access_token" -> "at-1", "token_type" -> "Bearer", "expires_in" -> "3600", "scope" -> "openid read")))
  }

  test("a refused token is carried through as the endpoint error") {
    val out = run(failure(OAuth2Error.InvalidGrant()), (None, Map.empty[String, String]))
    assertEquals(out, Left(OAuth2Error.InvalidGrant()))
  }
}
