package dev.oauth2.core

import cats.Monoid
import cats.syntax.traverse._

final case class Scope private (value: String)

object Scope {
  def from(raw: String): Either[ParseFailure, Scope] =
    if (raw.isEmpty) Left(ParseFailure("Scope", "empty"))
    else if (!raw.forall(isTokenChar)) Left(ParseFailure("Scope", "not a scope token"))
    else Right(new Scope(raw))

  private def isTokenChar(c: Char): Boolean =
    c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e)
}

final case class Scopes private (value: Set[Scope])

object Scopes {
  val empty: Scopes = new Scopes(Set.empty)

  def from(values: Iterable[String]): Either[ParseFailure, Scopes] =
    values.toVector.traverse(Scope.from).map(v => new Scopes(v.toSet))

  def of(values: Iterable[Scope]): Scopes = new Scopes(values.toSet)

  implicit val monoid: Monoid[Scopes] = new Monoid[Scopes] {
    def empty: Scopes = Scopes.empty

    def combine(x: Scopes, y: Scopes): Scopes = new Scopes(x.value | y.value)
  }

  def union(a: Scopes, b: Scopes): Scopes = monoid.combine(a, b)

  def intersect(a: Scopes, b: Scopes): Scopes = new Scopes(a.value & b.value)

  def isSubsetOf(a: Scopes, b: Scopes): Boolean = a.value.subsetOf(b.value)

  def contains(a: Scopes, scope: Scope): Boolean = a.value.contains(scope)
}
