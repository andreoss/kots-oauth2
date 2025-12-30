package kots.oauth2.http

import kots.oauth2.core.OAuth2Error
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
    "client_assertion",
    "client_assertion_type",
    "assertion",
    "authorization_details",
    "scope"
  )

  val deviceAuthorizationParameters: Set[String] = Set(
    "client_id",
    "client_secret",
    "scope",
    "resource"
  )

  val authorizeParameters: Set[String] = Set(
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource",
    "request_uri"
  )

  val parParameters: Set[String] = Set(
    "response_type",
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource"
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
          .fold(
            error => DecodeResult.Error(error.code, new IllegalArgumentException(error.code)),
            DecodeResult.Value(_)
          )
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
    StatusCode.TooManyRequests,
    StatusCode.InternalServerError,
    StatusCode.ServiceUnavailable
  )

  val RetryAfterHeader: String = "Retry-After"

  def errorBody(status: StatusCode): Mapping[Map[String, String], OAuth2Error] =
    Mapping.fromDecode[Map[String, String], OAuth2Error](body => decoded(status, body))(_.body)

  def challengedBody(status: StatusCode): Mapping[(Option[String], Map[String, String]), OAuth2Error] =
    Mapping.fromDecode[(Option[String], Map[String, String]), OAuth2Error](carried =>
      decoded(status, carried._2)
    )(error => (error.challenge, error.body))

  def retriedBody(status: StatusCode): Mapping[(Option[String], Map[String, String]), OAuth2Error] =
    Mapping.fromDecode[(Option[String], Map[String, String]), OAuth2Error] { carried =>
      decoded(status, carried._2) match {
        case DecodeResult.Value(limited: OAuth2Error.RateLimited) =>
          DecodeResult.Value(
            limited.copy(retryAfter = carried._1.flatMap(_.toLongOption).getOrElse(0L))
          )
        case other => other
      }
    } {
      case limited: OAuth2Error.RateLimited => (Some(limited.retryAfter.toString), limited.body)
      case error                            => (None, error.body)
    }

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
          header[Option[String]](Endpoints.ChallengeHeader)
            .and(jsonBody[Map[String, String]])
            .map(challengedBody(status))
        )
      )(matches)
    else if (status == StatusCode.TooManyRequests)
      oneOfVariantValueMatcher(
        status,
        noStore(
          header[Option[String]](RetryAfterHeader)
            .and(jsonBody[Map[String, String]])
            .map(retriedBody(status))
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

  val DpopHeader: String = "DPoP"

  val ClientCertHeader: String = "X-Client-Cert"

  val TokenPath: String = "token"

  val token: PublicEndpoint[
    (Option[String], Map[String, String], Option[String], Option[String]),
    OAuth2Error,
    Map[String, Json],
    Any
  ] =
    endpoint.post
      .in(TokenPath)
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .in(header[Option[String]](DpopHeader))
      .in(header[Option[String]](ClientCertHeader))
      .out(noStore(jsonBody[Map[String, Json]]))
      .errorOut(errors)

  lazy val revocation: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Unit, Any] =
    Revocation.endpoint

  val RevocationPath: String = "revocation"

  val DeviceAuthorizationPath: String = "device_authorization"

  lazy val deviceAuthorization
      : PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, Json], Any] =
    DeviceAuthorization.endpoint

  val ParPath: String = "par"

  lazy val par: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, Json], Any] =
    PushedAuthorization.endpoint

  val RegisterPath: String = "register"

  lazy val register: PublicEndpoint[Map[String, Json], OAuth2Error, Map[String, Json], Any] =
    sttp.tapir.endpoint.post
      .in(RegisterPath)
      .in(jsonBody[Map[String, Json]])
      .out(statusCode(StatusCode.Created).and(noStore(jsonBody[Map[String, Json]])))
      .errorOut(authorizeErrors)

  lazy val registrationRead: PublicEndpoint[(String, Option[String]), OAuth2Error, Map[String, Json], Any] =
    sttp.tapir.endpoint.get
      .in(RegisterPath)
      .in(path[String]("client_id"))
      .in(Auth.bearer)
      .out(noStore(jsonBody[Map[String, Json]]))
      .errorOut(errors)

  lazy val registrationUpdate
      : PublicEndpoint[(String, Option[String], Map[String, Json]), OAuth2Error, Map[String, Json], Any] =
    sttp.tapir.endpoint.put
      .in(RegisterPath)
      .in(path[String]("client_id"))
      .in(Auth.bearer)
      .in(jsonBody[Map[String, Json]])
      .out(noStore(jsonBody[Map[String, Json]]))
      .errorOut(errors)

  lazy val registrationDelete: PublicEndpoint[(String, Option[String]), OAuth2Error, Unit, Any] =
    sttp.tapir.endpoint.delete
      .in(RegisterPath)
      .in(path[String]("client_id"))
      .in(Auth.bearer)
      .out(noStore(statusCode(StatusCode.NoContent)))
      .errorOut(errors)

  lazy val introspection
      : PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, Json], Any] =
    Introspection.endpoint

  val WellKnownPath: List[String] = List(".well-known", "oauth-authorization-server")

  lazy val metadata: PublicEndpoint[Unit, OAuth2Error, Map[String, Json], Any] =
    WellKnownPath
      .foldLeft(sttp.tapir.endpoint.get)((path, segment) => path.in(segment))
      .out(cacheable(jsonBody[Map[String, Json]]))
      .errorOut(documentErrors)

  val WellKnownResourcePath: List[String] = List(".well-known", "oauth-protected-resource")

  lazy val resourceMetadata: PublicEndpoint[Unit, OAuth2Error, Map[String, Json], Any] =
    WellKnownResourcePath
      .foldLeft(sttp.tapir.endpoint.get)((path, segment) => path.in(segment))
      .out(cacheable(jsonBody[Map[String, Json]]))
      .errorOut(documentErrors)

  val HealthPath: String = "health"

  lazy val health: PublicEndpoint[Unit, OAuth2Error, Map[String, Json], Any] =
    sttp.tapir.endpoint.get
      .in(HealthPath)
      .out(noStore(jsonBody[Map[String, Json]]))
      .errorOut(documentErrors)

  val ReadyPath: String = "ready"

  lazy val ready: PublicEndpoint[Unit, OAuth2Error, (StatusCode, Map[String, Json]), Any] =
    sttp.tapir.endpoint.get
      .in(ReadyPath)
      .out(statusCode.and(noStore(jsonBody[Map[String, Json]])))
      .errorOut(documentErrors)

  val JwksPath: String = "jwks"

  val IntrospectionPath: String = "introspection"

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
      .in(Endpoints.RevocationPath)
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(Endpoints.noStore(statusCode(StatusCode.Ok)))
      .errorOut(Endpoints.errors)
}

private[http] object PushedAuthorization {

  implicit val formParameters: Codec[String, Map[String, String], XWwwFormUrlencoded] =
    Endpoints.strictForm(Endpoints.parParameters)

  val endpoint: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, Json], Any] =
    sttp.tapir.endpoint.post
      .in(Endpoints.ParPath)
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(statusCode(StatusCode.Created).and(Endpoints.noStore(jsonBody[Map[String, Json]])))
      .errorOut(Endpoints.errors)
}

private[http] object DeviceAuthorization {

  implicit val formParameters: Codec[String, Map[String, String], XWwwFormUrlencoded] =
    Endpoints.strictForm(Endpoints.deviceAuthorizationParameters)

  val endpoint: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, Json], Any] =
    sttp.tapir.endpoint.post
      .in(Endpoints.DeviceAuthorizationPath)
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(Endpoints.noStore(jsonBody[Map[String, Json]]))
      .errorOut(Endpoints.errors)
}

private[http] object Introspection {

  implicit val formParameters: Codec[String, Map[String, String], XWwwFormUrlencoded] =
    Endpoints.strictForm(Endpoints.introspectionParameters)

  val endpoint: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, Json], Any] =
    sttp.tapir.endpoint.post
      .in(Endpoints.IntrospectionPath)
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(Endpoints.noStore(jsonBody[Map[String, Json]]))
      .errorOut(Endpoints.errors)
}
