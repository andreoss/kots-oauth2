package kots.oauth2.core

import cats.data.ValidatedNec
import cats.syntax.all._

private[core] object Params {

  def required[A](params: Map[String, String], name: String)(
      parse: String => Either[OAuth2Error, A]
  ): ValidatedNec[OAuth2Error, A] =
    params.get(name) match {
      case None    => OAuth2Error.InvalidRequest(Some(s"missing $name")).invalidNec
      case Some(v) => parse(v).toValidatedNec
    }

  def optional[A](params: Map[String, String], name: String)(
      parse: String => Either[OAuth2Error, A]
  ): ValidatedNec[OAuth2Error, Option[A]] =
    params.get(name).traverse(parse).toValidatedNec

  def field[A](params: Map[String, String], name: String)(
      parse: String => Either[ParseFailure, A]
  ): ValidatedNec[OAuth2Error, A] =
    required(params, name)(raw => parse(raw).leftMap(OAuth2Error.fromParseFailure))

  def fieldOpt[A](params: Map[String, String], name: String)(
      parse: String => Either[ParseFailure, A]
  ): ValidatedNec[OAuth2Error, Option[A]] =
    optional(params, name)(raw => parse(raw).leftMap(OAuth2Error.fromParseFailure))
}
