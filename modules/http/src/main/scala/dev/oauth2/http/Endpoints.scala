package dev.oauth2.http

import dev.oauth2.core.OAuth2Error
import sttp.model.StatusCode
import sttp.tapir.CodecFormat.XWwwFormUrlencoded
import sttp.tapir._
import sttp.tapir.json.circe._

object Endpoints {

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

  implicit val formParameters: Codec[String, Map[String, String], XWwwFormUrlencoded] =
    Codec
      .id[String, XWwwFormUrlencoded](XWwwFormUrlencoded(), Schema.anyObject)
      .mapDecode(raw =>
        Form
          .parse(raw)
          .flatMap(params => Form.strict(params, tokenParameters))
          .fold(error => DecodeResult.Error(error.code, new IllegalArgumentException(error.code)), DecodeResult.Value(_))
      )(Form.render)

  val statuses: List[StatusCode] = List(
    StatusCode.BadRequest,
    StatusCode.Unauthorized,
    StatusCode.Forbidden,
    StatusCode.InternalServerError,
    StatusCode.ServiceUnavailable
  )

  def errorBody(status: StatusCode): Mapping[Map[String, String], OAuth2Error] =
    Mapping.fromDecode[Map[String, String], OAuth2Error](body =>
      OAuth2Error
        .fromWire(status.code, body)
        .fold(
          failure => DecodeResult.Error(status.code.toString, new IllegalArgumentException(failure.toString)),
          DecodeResult.Value(_)
        )
    )(_.body)

  private def errorVariant(status: StatusCode): EndpointOutput.OneOfVariant[OAuth2Error] =
    oneOfVariantValueMatcher(status, jsonBody[Map[String, String]].map(errorBody(status))) {
      case error: OAuth2Error => error.status == status.code
    }

  val token: PublicEndpoint[(Option[String], Map[String, String]), OAuth2Error, Map[String, String], Any] =
    endpoint.post
      .in("token")
      .in(header[Option[String]]("Authorization"))
      .in(formBody[Map[String, String]])
      .out(jsonBody[Map[String, String]])
      .errorOut(oneOf[OAuth2Error](errorVariant(statuses.head), statuses.tail.map(errorVariant): _*))
}
