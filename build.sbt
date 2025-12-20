import scoverage.ScoverageKeys._

val Scala2 = "2.13.18"
val Scala3 = "3.3.6"
val Tapir = "1.11.50"
val Circe = "0.14.16"
val Http4s = "0.23.30"

ThisBuild / organization := "kots.oauth2"
ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / scalaVersion := Scala2
ThisBuild / crossScalaVersions := Seq(Scala2, Scala3)

ThisBuild / coverageMinimumStmtTotal := 85
ThisBuild / coverageFailOnMinimum := true
ThisBuild / coverageHighlighting := false

lazy val commonSettings = Seq(
  scalacOptions ++= Seq(
    "-encoding",
    "utf8",
    "-deprecation",
    "-feature",
    "-Xfatal-warnings"
  ) ++ (CrossVersion.partialVersion(scalaVersion.value) match {
    case Some((2, 13)) => Seq("-Xlint", "-Wunused")
    case _             => Seq("-Wunused:all")
  }),
  Compile / console / scalacOptions := Seq.empty,
  Test / parallelExecution := false,
  testFrameworks += new TestFramework("munit.Framework")
)

lazy val testSettings = Seq(
  libraryDependencies ++= Seq(
    "org.scalameta" %% "munit" % "1.3.6" % Test,
    "org.scalameta" %% "munit-scalacheck" % "1.3.1" % Test,
    "org.typelevel" %% "cats-laws" % "2.12.0" % Test,
    "org.typelevel" %% "discipline-munit" % "2.0.0" % Test,
    "org.typelevel" %% "munit-cats-effect" % "2.1.0" % Test
  )
)

def module(id: String): Project =
  Project(id, file(s"modules/$id"))
    .settings(commonSettings, testSettings)
    .settings(name := s"oauth2-$id")

lazy val core =
  module("core")
    .settings(libraryDependencies += "org.typelevel" %% "cats-core" % "2.12.0")

lazy val jose = module("jose")
  .dependsOn(core)
  .settings(
    libraryDependencies ++= Seq(
      "io.circe" %% "circe-core" % Circe,
      "io.circe" %% "circe-parser" % Circe
    )
  )

lazy val store = module("store")
  .dependsOn(core % "compile->compile;test->test", jose % "compile->compile;test->test")
  .settings(libraryDependencies += "org.typelevel" %% "cats-effect" % "3.6.0")

lazy val http = module("http")
  .dependsOn(core, jose % "compile->compile;test->test")
  .settings(
    libraryDependencies ++= Seq(
      "com.softwaremill.sttp.tapir" %% "tapir-core" % Tapir,
      "com.softwaremill.sttp.tapir" %% "tapir-json-circe" % Tapir,
      "io.circe" %% "circe-core" % Circe,
      "io.circe" %% "circe-parser" % Circe,
      "com.softwaremill.sttp.tapir" %% "tapir-openapi-docs" % Tapir % Test
    )
  )

lazy val server = module("server").dependsOn(core, store, http, jose % "test->test")

lazy val client = module("client")
  .dependsOn(core % "compile->compile;test->test", jose % "compile->compile;test->test")
  .settings(
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-client" % Http4s,
      "io.circe" %% "circe-core" % Circe,
      "io.circe" %% "circe-parser" % Circe,
      "org.typelevel" %% "cats-effect-testkit" % "3.6.0" % Test
    )
  )

lazy val host = module("host")
  .dependsOn(server, client, jose % "test->test")
  .settings(
    Compile / run / mainClass := Some("kots.oauth2.host.DevServer"),
    libraryDependencies ++= Seq(
      "com.softwaremill.sttp.tapir" %% "tapir-http4s-server" % Tapir,
      "org.http4s" %% "http4s-ember-server" % Http4s,
      "org.http4s" %% "http4s-ember-client" % Http4s % Test,
      "org.typelevel" %% "cats-effect-testkit" % "3.6.0" % Test,
      "io.circe" %% "circe-parser" % Circe % Test
    )
  )

lazy val root = (project in file("."))
  .settings(commonSettings)
  .settings(name := "kots-oauth2", publish / skip := true)
  .aggregate(core, jose, store, http, server, client, host)

addCommandAlias("lint", "scalafmtCheckAll; scalafmtSbtCheck; scalafixAll --check")
