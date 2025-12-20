package kots.oauth2.core

import cats.Eq
import cats.kernel.laws.discipline.MonoidTests
import cats.syntax.eq._
import munit.DisciplineSuite
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalacheck.Prop._

class AuthorizationDetailsSpec extends DisciplineSuite {

  private val genType: Gen[AuthorizationDetailType] =
    Gen
      .choose(3, 12)
      .flatMap(n => Gen.listOfN(n, Gen.alphaLowerChar))
      .map(_.mkString)
      .map(raw => AuthorizationDetailType.from(raw).toOption.get)

  private val genLocation: Gen[Location] =
    Gen
      .choose(1, 8)
      .flatMap(n => Gen.listOfN(n, Gen.alphaLowerChar))
      .map(cs => s"https://example.com/${cs.mkString}")
      .map(raw => Location.from(raw).toOption.get)

  private val genAction: Gen[Action] =
    Gen
      .oneOf(Gen.const("read"), Gen.const("write"), Gen.const("delete"))
      .map(raw => Action.from(raw).toOption.get)

  private val genFields: Gen[Map[String, String]] =
    Gen.oneOf(
      Gen.const(Map.empty[String, String]),
      Gen.const(Map("identifier" -> "1")),
      Gen.const(Map("identifier" -> "2")),
      Gen.const(Map("datatype" -> "account"))
    )

  private val genDetail: Gen[AuthorizationDetail] =
    for {
      t <- genType
      ls <- Gen.listOf(genLocation).map(_.take(3))
      as <- Gen.listOf(genAction).map(_.take(3))
      fs <- genFields
    } yield AuthorizationDetail.of(t, ls, as, fs)

  private val genDetails: Gen[AuthorizationDetails] =
    Gen.listOf(genDetail).map(ds => AuthorizationDetails.of(ds.take(4)))

  implicit val arbDetails: Arbitrary[AuthorizationDetails] = Arbitrary(genDetails)
  implicit val eqDetails: Eq[AuthorizationDetails] = Eq.fromUniversalEquals

  checkAll("AuthorizationDetails.Monoid", MonoidTests[AuthorizationDetails].monoid)

  test("type parsing refuses empty, long and unprintable input") {
    assertEquals(
      AuthorizationDetailType.from("").isLeft,
      true
    )
    assertEquals(
      AuthorizationDetailType.from("a" * 513).isLeft,
      true
    )
    assertEquals(
      AuthorizationDetailType.from("payment\n").isLeft,
      true
    )
    assertEquals(
      AuthorizationDetailType.from("payment_initiation").isRight,
      true
    )
  }

  test("location parsing requires an absolute uri without a fragment") {
    assertEquals(Location.from("/relative").isLeft, true)
    assertEquals(Location.from("https://example.com/a#f").isLeft, true)
    assertEquals(Location.from("https://example.com/a").isRight, true)
  }

  test("action parsing refuses empty input") {
    assertEquals(Action.from("").isLeft, true)
    assertEquals(Action.from("read").isRight, true)
  }

  test("of removes duplicate locations and actions") {
    val t = AuthorizationDetailType.from("t").toOption.get
    val l = Location.from("https://example.com/a").toOption.get
    val a = Action.from("read").toOption.get
    val d = AuthorizationDetail.of(t, List(l, l), List(a, a))
    assertEquals(d.locations, List(l))
    assertEquals(d.actions, List(a))
  }

  test("union is idempotent and keeps both sides") {
    forAll(genDetails, genDetails) { (a, b) =>
      val ab = AuthorizationDetails.union(a, b)
      AuthorizationDetails.union(a, a) === a &&
      a.value.forall(ab.value.contains) &&
      b.value.forall(ab.value.contains)
    }
  }

  test("every detail covers itself") {
    forAll(genDetails) { ds =>
      AuthorizationDetails.covers(ds, ds)
    }
  }

  test("empty request is covered by any granted details") {
    forAll(genDetails) { ds =>
      AuthorizationDetails.covers(ds, AuthorizationDetails.empty)
    }
  }

  test("a request is not covered by an empty grant") {
    forAll(genDetails) { ds =>
      !AuthorizationDetails.covers(AuthorizationDetails.empty, ds) || ds == AuthorizationDetails.empty
    }
  }

  test("coverage refuses a missing type") {
    val t1 = AuthorizationDetailType.from("one").toOption.get
    val t2 = AuthorizationDetailType.from("two").toOption.get
    val granted = AuthorizationDetails.of(List(AuthorizationDetail.of(t1)))
    val requested = AuthorizationDetails.of(List(AuthorizationDetail.of(t2)))
    assertEquals(AuthorizationDetails.covers(granted, requested), false)
  }

  test("coverage refuses a location, action or field outside the grant") {
    val t = AuthorizationDetailType.from("one").toOption.get
    val l1 = Location.from("https://example.com/a").toOption.get
    val l2 = Location.from("https://example.com/b").toOption.get
    val a1 = Action.from("read").toOption.get
    val a2 = Action.from("write").toOption.get
    val granted =
      AuthorizationDetails.of(List(AuthorizationDetail.of(t, List(l1), List(a1), Map("id" -> "1"))))
    assertEquals(
      AuthorizationDetails
        .covers(granted, AuthorizationDetails.of(List(AuthorizationDetail.of(t, List(l2))))),
      false
    )
    assertEquals(
      AuthorizationDetails
        .covers(granted, AuthorizationDetails.of(List(AuthorizationDetail.of(t, Nil, List(a2))))),
      false
    )
    assertEquals(
      AuthorizationDetails.covers(
        granted,
        AuthorizationDetails.of(List(AuthorizationDetail.of(t, Nil, Nil, Map("id" -> "2"))))
      ),
      false
    )
    assertEquals(
      AuthorizationDetails.covers(
        granted,
        AuthorizationDetails.of(List(AuthorizationDetail.of(t, List(l1), List(a1), Map("id" -> "1"))))
      ),
      true
    )
  }

  test("coverage requires every requested detail to be covered") {
    val t1 = AuthorizationDetailType.from("one").toOption.get
    val t2 = AuthorizationDetailType.from("two").toOption.get
    val granted = AuthorizationDetails.of(List(AuthorizationDetail.of(t1)))
    val requested = AuthorizationDetails.of(List(AuthorizationDetail.of(t1), AuthorizationDetail.of(t2)))
    assertEquals(AuthorizationDetails.covers(granted, requested), false)
  }
}
