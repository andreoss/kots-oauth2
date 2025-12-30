package kots.oauth2.server

import kots.oauth2.core.ClientId
import kots.oauth2.core.OAuth2Error
import kots.oauth2.store.Client

private[server] object ClientIdentity {

  val Parameter: String = "client_id"

  def named(parameters: Map[String, String], client: Client): Either[OAuth2Error, Map[String, String]] =
    parameters.get(Parameter) match {
      case None      => Right(parameters + (Parameter -> client.id.value))
      case Some(raw) =>
        ClientId.from(raw) match {
          case Right(declared) if declared != client.id =>
            Left(OAuth2Error.InvalidClient(): OAuth2Error)
          case _ => Right(parameters)
        }
    }
}
