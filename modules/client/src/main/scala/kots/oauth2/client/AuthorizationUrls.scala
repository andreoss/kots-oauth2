package kots.oauth2.client

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

import cats.Monad
import cats.syntax.flatMap._
import cats.syntax.functor._

import kots.oauth2.core.Acr
import kots.oauth2.core.ClientId
import kots.oauth2.core.CodeChallengeMethod
import kots.oauth2.core.CodeVerifier
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.Entropy
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Pkce
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.State
import kots.oauth2.core.Wire

final class AuthorizationUrls[F[_]: Monad](entropy: Entropy[F], endpoint: EndpointUri) {

  def begin(
      clientId: ClientId,
      redirectUri: RedirectUri,
      scope: Scopes,
      resource: Option[ResourceIndicator] = None,
      acr: Option[Acr] = None
  ): F[Either[ParseFailure, AuthorizationUrls.Ticket]] =
    for {
      verifierRaw <- entropy.bytes(AuthorizationUrls.VerifierEntropyBytes)
      stateRaw <- entropy.bytes(AuthorizationUrls.StateEntropyBytes)
    } yield for {
      verifier <- CodeVerifier.from(Entropy.hex(verifierRaw))
      challenge <- Pkce.challenge(verifier)
      state <- State.from(Entropy.hex(stateRaw))
    } yield AuthorizationUrls.Ticket(
      location(clientId, redirectUri, scope, state, challenge.value, resource, acr),
      verifier,
      state
    )

  private def location(
      clientId: ClientId,
      redirectUri: RedirectUri,
      scope: Scopes,
      state: State,
      challenge: String,
      resource: Option[ResourceIndicator],
      acr: Option[Acr]
  ): String = {
    val parameters =
      List(
        "response_type" -> "code",
        "client_id" -> clientId.value,
        "redirect_uri" -> redirectUri.value,
        "state" -> state.value,
        "code_challenge" -> challenge,
        "code_challenge_method" -> CodeChallengeMethod.S256.value
      ) ++
        (if (scope.value.isEmpty) Nil else List("scope" -> Wire[Scopes].encode(scope))) ++
        resource.map(value => "resource" -> value.value) ++
        acr.map(value => "acr_values" -> value.value)
    val query = parameters
      .map { case (name, value) => s"$name=${URLEncoder.encode(value, StandardCharsets.UTF_8.name)}" }
      .mkString("&")
    val separator = if (endpoint.value.contains("?")) "&" else "?"
    endpoint.value + separator + query
  }
}

object AuthorizationUrls {

  val VerifierEntropyBytes: Int = 32

  val StateEntropyBytes: Int = 16

  final case class Ticket(location: String, verifier: CodeVerifier, state: State)
}
