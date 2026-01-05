package dev.oauth2.http

import dev.oauth2.core.OAuth2Error
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop._

class FormSpec extends ScalaCheckSuite {

  private def code(decoded: Either[OAuth2Error, Map[String, String]]): Option[String] =
    decoded.left.toOption.map(_.code)

  private val characters: Vector[Char] =
    (('a' to 'z') ++ ('A' to 'Z') ++ ('0' to '9')).toVector

  private def nameOf(n: Int): Gen[String] =
    Gen.listOfN(n, Gen.choose(0, characters.length - 1).map(characters)).map(_.mkString)

  test("a form body decodes its parameters") {
    assertEquals(
      Form.parse("grant_type=authorization_code&code=abc"),
      Right(Map("grant_type" -> "authorization_code", "code" -> "abc"))
    )
  }

  test("an empty form body decodes to no parameters") {
    assertEquals(Form.parse(""), Right(Map.empty[String, String]))
  }

  test("a form body percent-decodes names and values") {
    assertEquals(Form.parse("scope=openid%20read"), Right(Map("scope" -> "openid read")))
    assertEquals(Form.parse("redirect_uri=https%3A%2F%2Fexample.com%2Fcb"), Right(Map("redirect_uri" -> "https://example.com/cb")))
    assertEquals(Form.parse("scope=openid+read"), Right(Map("scope" -> "openid read")))
  }

  test("a parameter without a value is refused") {
    assertEquals(code(Form.parse("grant_type")), Some("invalid_request"))
  }

  test("an empty parameter name is refused") {
    assertEquals(code(Form.parse("=value")), Some("invalid_request"))
    assertEquals(Form.parse("%20=value"), Right(Map(" " -> "value")))
  }

  test("a duplicated parameter is refused") {
    assertEquals(code(Form.parse("code=a&code=b")), Some("invalid_request"))
    assertEquals(code(Form.parse("code=a&other=b&code=a")), Some("invalid_request"))
  }

  test("a malformed percent encoding is refused") {
    assertEquals(code(Form.parse("scope=openid%2")), Some("invalid_request"))
    assertEquals(code(Form.parse("scope=openid%zz")), Some("invalid_request"))
  }

  test("an empty parameter value is kept") {
    assertEquals(Form.parse("scope="), Right(Map("scope" -> "")))
  }

  test("a strict form keeps the known parameters and refuses an unknown one") {
    val params = Map("grant_type" -> "authorization_code", "code" -> "abc")
    assertEquals(Form.strict(params, Set("grant_type", "code", "scope")), Right(params))
    assertEquals(code(Form.strict(params, Set("grant_type", "code"))), None)
    assertEquals(code(Form.strict(params, Set("grant_type"))), Some("invalid_request"))
  }

  test("a rendered form body is percent-encoded and ordered by name") {
    assertEquals(
      Form.render(Map("scope" -> "openid read", "redirect_uri" -> "https://example.com/cb")),
      "redirect_uri=https%3A%2F%2Fexample.com%2Fcb&scope=openid+read"
    )
  }

  test("an empty form renders to an empty body") {
    assertEquals(Form.render(Map.empty[String, String]), "")
  }

  property("a rendered form body decodes back to the same parameters") {
    forAll(nameOf(4), nameOf(6)) { (name, value) =>
      Form.parse(Form.render(Map(name -> value))) == Right(Map(name -> value))
    }
  }

  property("a decoded form round trips percent-encoded parameters") {
    forAll(nameOf(4), nameOf(8)) { (name, value) =>
      Form.parse(s"$name=${value.replace(" ", "+")}") == Right(Map(name -> value.replace(" ", "+").replace("+", " ")))
    }
  }

  property("a parameter repeated is always refused") {
    forAll(nameOf(4), nameOf(4)) { (name, value) =>
      (name != value) ==> {
        val once = Form.parse(s"$name=$value")
        val twice = Form.parse(s"$name=$value&$name=$value")
        once.isRight && code(twice).contains("invalid_request")
      }
    }
  }
}
