package dev.oauth2.server

import cats.Monad
import cats.syntax.functor._

import dev.oauth2.core.ClientAuthInput
import dev.oauth2.core.ClientAuthMethod
import dev.oauth2.core.ClientSecret
import dev.oauth2.core.ClientSecretHash
import dev.oauth2.core.OAuth2Error
import dev.oauth2.store.Client
import dev.oauth2.store.ClientStore

trait ClientAuthentication[F[_]] {
  def authenticate(input: ClientAuthInput): F[Either[OAuth2Error, Client]]
}

final class RegisteredClientAuthentication[F[_]: Monad](clients: ClientStore[F])
    extends ClientAuthentication[F] {

  def authenticate(input: ClientAuthInput): F[Either[OAuth2Error, Client]] =
    input.subject match {
      case None => Monad[F].pure(Left(RegisteredClientAuthentication.rejected))
      case Some(id) =>
        clients.find(id).map {
          case None        => Left(RegisteredClientAuthentication.rejected)
          case Some(client) => check(client, input)
        }
    }

  private def check(client: Client, input: ClientAuthInput): Either[OAuth2Error, Client] =
    if (input.clientId.exists(_ != client.id)) Left(RegisteredClientAuthentication.rejected)
    else
      client.authMethod match {
        case ClientAuthMethod.None =>
          Either.cond(
            input.basic.isEmpty && input.clientSecret.isEmpty,
            client,
            RegisteredClientAuthentication.rejected
          )
        case ClientAuthMethod.ClientSecretBasic =>
          input.basic match {
            case Some(credentials) => secret(client, credentials.secret)
            case None              => Left(RegisteredClientAuthentication.rejected)
          }
        case ClientAuthMethod.ClientSecretPost =>
          input.clientSecret match {
            case Some(candidate) => secret(client, candidate)
            case None            => Left(RegisteredClientAuthentication.rejected)
          }
      }

  private def secret(client: Client, candidate: ClientSecret): Either[OAuth2Error, Client] =
    client.secretHash match {
      case Some(hash) =>
        Either.cond(
          ClientSecretHash.verify(hash, candidate),
          client,
          RegisteredClientAuthentication.rejected
        )
      case None => Left(RegisteredClientAuthentication.rejected)
    }
}

object RegisteredClientAuthentication {
  private val rejected: OAuth2Error = OAuth2Error.InvalidClient()
}
