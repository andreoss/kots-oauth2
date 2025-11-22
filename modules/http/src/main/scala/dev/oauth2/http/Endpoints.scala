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

  val tokenParameters: Set[String] = Set(
    "grant_type",
    "code",
    "refresh_token",
    "redirect_uri",
    "code_verifier",
    "client_id",
    "client_secret",
    "scope"
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

  val token: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any] =
    endpoint.post
      .in("token")
      .in(Auth.basic)
      .in(formBody[Map[String, String]])
      .out(noStore(jsonBody[Map[String, String]]))
      .errorOut(errors)

  lazy val revocation: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Unit, Any] =
    Revocation.endpoint

  lazy val introspection
      : PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any] =
    Introspection.endpoint

  val WellKnownPath: List[String] = List(".well-known", "oauth-authorization-server")

  lazy val metadata: PublicEndpoint[Unit, OAuth2Error, Map[String, Json], Any] =
    WellKnownPath
      .foldLeft(sttp.tapir.endpoint.get)((path, segment) => path.in(segment))
      .out(noStore(jsonBody[Map[String, Json]]))
      .errorOut(errors)
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
