package dev.oauth2.core

import cats.Eq
import cats.kernel.laws.discipline.MonoidTests
import cats.syntax.eq._
import munit.DisciplineSuite
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalacheck.Prop._

class ScopeSpec extends DisciplineSuite {

  private val genScope: Gen[Scope] =
    Gen
      .choose(1, 8)
      .flatMap(n => Gen.listOfN(n, Gen.alphaLowerChar))
      .map(_.mkString)
      .map(raw => Scope.from(raw).toOption.get)

  private val genScopes: Gen[Scopes] =
    Gen.listOf(genScope).map(values => Scopes.of(values))

  implicit val arbScope: Arbitrary[Scope] = Arbitrary(genScope)
  implicit val arbScopes: Arbitrary[Scopes] = Arbitrary(genScopes)
  implicit val eqScopes: Eq[Scopes] = Eq.fromUniversalEquals

  checkAll("Scopes.Monoid", MonoidTests[Scopes].monoid)

  property("union is idempotent and commutative") {
    forAll(genScopes, genScopes) { (a, b) =>
      val ab = Scopes.union(a, b)
      Scopes.union(a, a) === a && ab === Scopes.union(b, a)
    }
  }

  property("intersection is idempotent and commutative") {
    forAll(genScopes, genScopes) { (a, b) =>
      val ab = Scopes.intersect(a, b)
      Scopes.intersect(a, a) === a && ab === Scopes.intersect(b, a)
    }
  }

  property("intersection is a subset of both operands") {
    forAll(genScopes, genScopes) { (a, b) =>
      val ab = Scopes.intersect(a, b)
      Scopes.isSubsetOf(ab, a) && Scopes.isSubsetOf(ab, b)
    }
  }

  property("union absorbs intersection") {
    forAll(genScopes, genScopes) { (a, b) =>
      Scopes.union(a, Scopes.intersect(a, b)) === a
    }
  }

  property("empty is the unit of union and the bottom of subset") {
    forAll(genScopes) { a =>
      Scopes.union(a, Scopes.empty) === a && Scopes.isSubsetOf(Scopes.empty, a)
    }
  }

  property("subset is antisymmetric") {
    forAll(genScopes, genScopes) { (a, b) =>
      (Scopes.isSubsetOf(a, b) && Scopes.isSubsetOf(b, a)) == (a === b)
    }
  }

  test("union, intersection and subset agree with set semantics") {
    val read = Scopes.of(List(Scope.from("read").toOption.get))
    val write = Scopes.of(List(Scope.from("write").toOption.get))
    val both = Scopes.union(read, write)
    assertEquals(Scopes.contains(both, Scope.from("read").toOption.get), true)
    assertEquals(Scopes.contains(both, Scope.from("openid").toOption.get), false)
    assertEquals(Scopes.intersect(both, read), read)
    assertEquals(Scopes.isSubsetOf(read, both), true)
    assertEquals(Scopes.isSubsetOf(both, read), false)
  }
}
