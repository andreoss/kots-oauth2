package dev.oauth2.host

import cats.effect.ExitCode
import cats.effect.IO
import cats.effect.IOApp

import dev.oauth2.jose.Jwks
import dev.oauth2.store.memory.InMemoryKeyStore

object KeysTool extends IOApp {

  def run(args: List[String]): IO[ExitCode] =
    args match {
      case "generate" :: Nil => generate.as(ExitCode.Success)
      case "rotate" :: Nil   => rotate.as(ExitCode.Success)
      case _                 => IO.println("usage: generate | rotate").as(ExitCode.Error)
    }

  private def generate: IO[Unit] =
    command.flatMap { case (tool, store) =>
      tool.generate.flatMap {
        case Left(failure)    => IO.println(s"${failure.typeName}: ${failure.reason}")
        case Right(generated) => store.jwks.flatMap(published => print(published, generated))
      }
    }

  private def rotate: IO[Unit] =
    command.flatMap { case (tool, store) =>
      tool.generate >> tool.rotate.flatMap {
        case Left(failure)  => IO.println(s"${failure.typeName}: ${failure.reason}")
        case Right(rotated) =>
          IO.println(s"retired: ${rotated.retired.fold("none")(_.value)}") >>
            store.jwks.flatMap(published => print(published, rotated.generated))
      }
    }

  private def command: IO[(KeyCommand[IO], InMemoryKeyStore[IO])] =
    for {
      entropy <- Development.secureEntropy[IO]
      store <- InMemoryKeyStore.create[IO]
    } yield (new KeyCommand[IO](store, entropy), store)

  private def print(published: Jwks, generated: KeyCommand.Generated): IO[Unit] =
    IO.println(io.circe.Json.fromFields(dev.oauth2.http.JwkSet.render(published)).spaces2) >>
      IO.println(KeyCommand.pem(generated.privateKey))
}
