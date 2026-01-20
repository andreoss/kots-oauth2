package kots.oauth2.host

import java.sql.DriverManager

import cats.effect.ExitCode
import cats.effect.IO
import cats.effect.IOApp

import kots.oauth2.store.sql.Migrations
import kots.oauth2.store.sql.Schema

object MigrateTool extends IOApp {

  val Usage: String = "usage: version | next | apply | verify <jdbc-url>"

  def run(args: List[String]): IO[ExitCode] =
    args match {
      case command :: url :: Nil => attempted(command, url)
      case _                     => IO.println(Usage).as(ExitCode.Error)
    }

  private def attempted(command: String, url: String): IO[ExitCode] =
    dispatch(command, url).handleErrorWith(failure =>
      IO.println(s"failed: ${failure.getMessage}").as(ExitCode.Error)
    )

  private def dispatch(command: String, url: String): IO[ExitCode] =
    Migrations.of(connect(url), Schema.migrations) match {
      case Left(reason)      => IO.println(reason).as(ExitCode.Error)
      case Right(migrations) =>
        command match {
          case "version" =>
            migrations.version.flatMap(version => IO.println(s"version: $version")).as(ExitCode.Success)
          case "next" =>
            migrations.pending
              .flatMap {
                case Nil   => IO.println("next: none")
                case steps => IO.println("next: " + steps.map(_.version).mkString(" "))
              }
              .as(ExitCode.Success)
          case "apply" =>
            migrations.apply.flatMap {
              case Right(version) => IO.println(s"applied: $version").as(ExitCode.Success)
              case Left(reason)   => IO.println(reason).as(ExitCode.Error)
            }
          case "verify" =>
            migrations.verify.flatMap {
              case Right(version) => IO.println(s"verified: $version").as(ExitCode.Success)
              case Left(reason)   => IO.println(reason).as(ExitCode.Error)
            }
          case _ => IO.println(Usage).as(ExitCode.Error)
        }
    }

  private def connect(url: String): IO[java.sql.Connection] =
    IO.blocking(DriverManager.getConnection(url))
}
