package kots.oauth2.http

import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

import kots.oauth2.core.OAuth2Error

object Form {

  def render(params: Map[String, String]): String =
    params.toVector
      .sortBy(_._1)
      .map { case (name, value) => s"${encode(name)}=${encode(value)}" }
      .mkString("&")

  def parse(body: String): Either[OAuth2Error, Map[String, String]] =
    if (body.isEmpty) Right(Map.empty)
    else
      body
        .split("&", -1)
        .toVector
        .foldLeft(Right(Vector.empty): Either[OAuth2Error, Vector[(String, String)]]) { (acc, part) =>
          acc.flatMap(entries => parameter(part).map(entries :+ _))
        }
        .flatMap(collect)

  def strict(params: Map[String, String], allowed: Set[String]): Either[OAuth2Error, Map[String, String]] =
    params.keys.toVector.sorted.find(name => !allowed.contains(name)) match {
      case Some(name) => Left(OAuth2Error.InvalidRequest(Some(s"unknown parameter: $name")))
      case None       => Right(params)
    }

  private def parameter(part: String): Either[OAuth2Error, (String, String)] =
    part.indexOf('=') match {
      case -1    => Left(OAuth2Error.InvalidRequest(Some("parameter without a value")))
      case 0     => Left(OAuth2Error.InvalidRequest(Some("empty parameter name")))
      case index =>
        decode(part.substring(0, index)).flatMap { name =>
          if (name.isEmpty) Left(OAuth2Error.InvalidRequest(Some("empty parameter name")))
          else decode(part.substring(index + 1)).map(value => name -> value)
        }
    }

  private def collect(entries: Vector[(String, String)]): Either[OAuth2Error, Map[String, String]] =
    entries.foldLeft(Right(Map.empty): Either[OAuth2Error, Map[String, String]]) { (acc, entry) =>
      acc.flatMap { params =>
        if (params.contains(entry._1))
          Left(OAuth2Error.InvalidRequest(Some(s"duplicated parameter: ${entry._1}")))
        else Right(params + entry)
      }
    }

  private def encode(raw: String): String = URLEncoder.encode(raw, StandardCharsets.UTF_8)

  private def decode(raw: String): Either[OAuth2Error, String] =
    try Right(URLDecoder.decode(raw, StandardCharsets.UTF_8))
    catch {
      case _: IllegalArgumentException => Left(OAuth2Error.InvalidRequest(Some("malformed percent encoding")))
    }
}
