package dev.oauth2.http

import dev.oauth2.core.OAuth2Error
import io.circe.Json
import sttp.model.StatusCode
import sttp.tapir.CodecFormat.XWwwFormUrlencoded
import sttp.tapir._
import sttp.tapir.json.circe._

object Endpoints {

  val ChallengeHeader: String = "WWW-Authenticate"

  val CacheControlHeader: String = "Cache-Control"

  val NoStore: String = "no-store"

  val PublicCacheSeconds: Long = 300L

  val PublicCache: String = s"max-age=$PublicCacheSeconds"

  val tokenParameters: Set[String] = Set(
    "grant_type",
    "code",
    "refresh_token",
    "redirect_uri",
    "code_verifier",
    "device_code",
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "requested_token_type",
    "audience",
    "resource",
    "client_id",
    "client_secret",
    "scope"
  )

  val deviceAuthorizationParameters: Set[String] = Set(
    "client_id",
    "client_secret",
    "scope"
  )

  val authorizeParameters: Set[String] = Set(
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method"
  )

  val revocationParameters: Set[String] = Set(
    "token",
    "token_type_hint",
    "client_id",
    "client_secret"
  )

  val introspectionParameters: Set[String] = revocationParameters

  def strictForm(allowed: Set[String]): Codec[String, Map[String, String], XWwwFormUrlencoded] =
    Codec
      .id[String, XWwwFormUrlencoded](XWwwFormUrlencoded(), Schema.anyObject)
      .mapDecode(raw =>
        Form
          .parse(raw)
          .flatMap(params => Form.strict(params, allowed))
          .fold(error => DecodeResult.Error(error.code, new IllegalArgumentException(error.code)), DecodeResult.Value(_))
      )(Form.render)

  implicit val formParameters: Codec[String, Map[String, String], XWwwFormUrlencoded] =
    strictForm(tokenParameters)

  def strictQuery(allowed: Set[String]): sttp.model.QueryParams => DecodeResult[Map[String, String]] =
    params =>
      params.toMultiSeq.collectFirst { case (name, values) if values.sizeIs > 1 => name } match {
        case Some(name) =>
          DecodeResult.Error(name, new IllegalArgumentException(s"duplicated parameter: $name"))
        case None =>
          Form
            .strict(params.toMap, allowed)
            .fold(
              error => DecodeResult.Error(error.code, new IllegalArgumentException(error.code)),
              DecodeResult.Value(_)
            )
      }

  val statuses: List[StatusCode] = List(
    StatusCode.BadRequest,
    StatusCode.Unauthorized,
    StatusCode.Forbidden,
    StatusCode.InternalServerError,
    StatusCode.ServiceUnavailable
  )

  def errorBody(status: StatusCode): Mapping[Map[String, String], OAuth2Error] =
    Mapping.fromDecode[Map[String, String], OAuth2Error](body => decoded(status, body))(_.body)

  def challengedBody(status: StatusCode): Mapping[(Option[String], Map[String, String]), OAuth2Error] =
    Mapping.fromDecode[(Option[String], Map[String, String]), OAuth2Error](carried => decoded(status, carried._2))(error =>
      (error.challenge, error.body)
    )

  private def decoded(status: StatusCode, body: Map[String, String]): DecodeResult[OAuth2Error] =
    OAuth2Error
      .fromWire(status.code, body)
      .fold(
        failure => DecodeResult.Error(status.code.toString, new IllegalArgumentException(failure.toString)),
        DecodeResult.Value(_)
      )

  private[http] def noStore[A](out: EndpointOutput[A]): EndpointOutput[A] =
    out.and(header(Endpoints.CacheControlHeader, Endpoints.NoStore))

  private[http] def cacheable[A](out: EndpointOutput[A]): EndpointOutput[A] =
    out.and(header(Endpoints.CacheControlHeader, Endpoints.PublicCache))

  private def errorVariant(status: StatusCode): EndpointOutput.OneOfVariant[OAuth2Error] = {
    val matches: PartialFunction[Any, Boolean] = { case error: OAuth2Error => error.status == status.code }
    if (status == StatusCode.Unauthorized)
      oneOfVariantValueMatcher(
        status,
        noStore(
          header[Option[String]](Endpoints.ChallengeHeader).and(jsonBody[Map[String, String]]).map(challengedBody(status))
        )
      )(matches)
    else
      oneOfVariantValueMatcher(status, noStore(jsonBody[Map[String, String]].map(errorBody(status))))(matches)
  }

  def errors: EndpointOutput[OAuth2Error] =
    oneOf[OAuth2Error](errorVariant(statuses.head), statuses.tail.map(errorVariant): _*)

  def documentErrors: EndpointOutput[OAuth2Error] =
    oneOf[OAuth2Error](
      errorVariant(StatusCode.InternalServerError),
      errorVariant(StatusCode.ServiceUnavailable)
    )

  val AuthorizePath: String = "authorize"

  val LocationHeader: String = "Location"

  val ReferrerPolicyHeader: String = "Referrer-Policy"

  val NoReferrer: String = "no-referrer"

  def authorizeErrors: EndpointOutput[OAuth2Error] =
    oneOf[OAuth2Error](
      errorVariant(StatusCode.BadRequest),
      errorVariant(StatusCode.InternalServerError),
      errorVariant(StatusCode.ServiceUnavailable)
    )

  lazy val authorize: PublicEndpoint[Map[String, String], OAuth2Error, String, Any] =
    sttp.tapir.endpoint.get
      .in(AuthorizePath)
      .in(queryParams.mapDecode(strictQuery(authorizeParameters))(sttp.model.QueryParams.fromMap))
      .out(
        statusCode(StatusCode.Found)
          .and(noStore(header[String](LocationHeader)))
          .and(header(ReferrerPolicyHeader, NoReferrer))
      )
      .errorOut(authorizeErrors)

  val token: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any] =
    endpoint.post
      .in("token")
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(noStore(jsonBody[Map[String, String]]))
      .errorOut(errors)

  lazy val revocation: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Unit, Any] =
    Revocation.endpoint

  val DeviceAuthorizationPath: String = "device_authorization"

  lazy val deviceAuthorization
      : PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any] =
    DeviceAuthorization.endpoint

  lazy val introspection
      : PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any] =
    Introspection.endpoint

  val WellKnownPath: List[String] = List(".well-known", "oauth-authorization-server")

  lazy val metadata: PublicEndpoint[Unit, OAuth2Error, Map[String, Json], Any] =
    WellKnownPath
      .foldLeft(sttp.tapir.endpoint.get)((path, segment) => path.in(segment))
      .out(cacheable(jsonBody[Map[String, Json]]))
      .errorOut(documentErrors)

  val JwksPath: String = "jwks"

  val JwkSetMediaType: String = "application/jwk-set+json"

  private[http] final case class JwkSetJson() extends CodecFormat {
    override val mediaType: sttp.model.MediaType =
      sttp.model.MediaType.unsafeParse(JwkSetMediaType)
  }

  private val jwkSet: Codec[String, Map[String, Json], JwkSetJson] =
    Codec
      .id[String, JwkSetJson](JwkSetJson(), Schema.anyObject)
      .mapDecode { raw =>
        io.circe.parser.parse(raw).map(_.asObject) match {
          case Right(Some(fields)) => DecodeResult.Value(fields.toMap)
          case Right(None)         => DecodeResult.Error(raw, new IllegalArgumentException(JwkSetMediaType))
          case Left(error)         => DecodeResult.Error(raw, error)
        }
      }(fields => Json.fromFields(fields).noSpaces)

  lazy val jwks: PublicEndpoint[Unit, OAuth2Error, Map[String, Json], Any] =
    sttp.tapir.endpoint.get
      .in(JwksPath)
      .out(cacheable(stringBodyUtf8AnyFormat(jwkSet)))
      .errorOut(documentErrors)
}

private[http] object Revocation {

  implicit val formParameters: Codec[String, Map[String, String], XWwwFormUrlencoded] =
    Endpoints.strictForm(Endpoints.revocationParameters)

  val endpoint: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Unit, Any] =
    sttp.tapir.endpoint.post
      .in("revocation")
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(Endpoints.noStore(statusCode(StatusCode.Ok)))
      .errorOut(Endpoints.errors)
}

private[http] object DeviceAuthorization {

  implicit val formParameters: Codec[String, Map[String, String], XWwwFormUrlencoded] =
    Endpoints.strictForm(Endpoints.deviceAuthorizationParameters)

  val endpoint: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any] =
    sttp.tapir.endpoint.post
      .in(Endpoints.DeviceAuthorizationPath)
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(Endpoints.noStore(jsonBody[Map[String, String]]))
      .errorOut(Endpoints.errors)
}

private[http] object Introspection {

  implicit val formParameters: Codec[String, Map[String, String], XWwwFormUrlencoded] =
    Endpoints.strictForm(Endpoints.introspectionParameters)

  val endpoint: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any] =
    sttp.tapir.endpoint.post
      .in("introspection")
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(Endpoints.noStore(jsonBody[Map[String, String]]))
      .errorOut(Endpoints.errors)
}
