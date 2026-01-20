package kots.oauth2.core

trait Wire[A] {
  def encode(value: A): String

  def decode(raw: String): Either[ParseFailure, A]
}

object Wire {

  def apply[A](implicit instance: Wire[A]): Wire[A] = instance

  def instance[A](encoder: A => String, decoder: String => Either[ParseFailure, A]): Wire[A] =
    new Wire[A] {
      def encode(value: A): String = encoder(value)

      def decode(raw: String): Either[ParseFailure, A] = decoder(raw)
    }

  implicit val clientId: Wire[ClientId] = instance(_.value, ClientId.from)

  implicit val clientSecret: Wire[ClientSecret] = instance(_.value, ClientSecret.from)

  implicit val subject: Wire[Subject] = instance(_.value, Subject.from)

  implicit val grantId: Wire[GrantId] = instance(_.value, GrantId.from)

  implicit val audience: Wire[Audience] = instance(_.value, Audience.from)

  implicit val keyId: Wire[KeyId] = instance(_.value, KeyId.from)

  implicit val state: Wire[State] = instance(_.value, State.from)

  implicit val issuer: Wire[Issuer] = instance(_.value, Issuer.from)

  implicit val authorizationCode: Wire[AuthorizationCode] =
    instance(_.value, AuthorizationCode.from)

  implicit val deviceCode: Wire[DeviceCode] = instance(_.value, DeviceCode.from)

  implicit val userCode: Wire[UserCode] = instance(_.value, UserCode.from)

  implicit val accessToken: Wire[AccessToken] = instance(_.value, AccessToken.from)

  implicit val refreshToken: Wire[RefreshToken] = instance(_.value, RefreshToken.from)

  implicit val scope: Wire[Scope] = instance(_.value, Scope.from)

  implicit val scopes: Wire[Scopes] =
    instance(
      _.value.map(_.value).toVector.sorted.mkString(" "),
      raw => if (raw.isEmpty) Right(Scopes.empty) else Scopes.parse(raw)
    )

  implicit val redirectUri: Wire[RedirectUri] = instance(_.value, RedirectUri.from)

  implicit val resourceIndicator: Wire[ResourceIndicator] =
    instance(_.value, ResourceIndicator.from)

  implicit val codeVerifier: Wire[CodeVerifier] = instance(_.value, CodeVerifier.from)

  implicit val codeChallenge: Wire[CodeChallenge] = instance(_.value, CodeChallenge.from)

  implicit val codeChallengeMethod: Wire[CodeChallengeMethod] =
    instance(_.value, CodeChallengeMethod.from)

  implicit val authorizationDetailType: Wire[AuthorizationDetailType] =
    instance(_.value, AuthorizationDetailType.from)

  implicit val location: Wire[Location] = instance(_.value, Location.from)

  implicit val action: Wire[Action] = instance(_.value, Action.from)

  implicit val responseType: Wire[ResponseType] = instance(_.value, ResponseType.from)

  implicit val grantType: Wire[GrantType] = instance(_.value, GrantType.from)

  implicit val clientAuthMethod: Wire[ClientAuthMethod] =
    instance(_.value, ClientAuthMethod.from)

  implicit val revocationToken: Wire[RevocationToken] = instance(_.value, RevocationToken.from)

  implicit val tokenTypeHint: Wire[TokenTypeHint] = instance(_.value, TokenTypeHint.from)
}
