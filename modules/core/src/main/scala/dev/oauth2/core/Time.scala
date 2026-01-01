package dev.oauth2.core

trait Clock[F[_]] {
  def instant: F[java.time.Instant]
}

object Clock {
  def apply[F[_]](implicit clock: Clock[F]): Clock[F] = clock

  def constant(at: java.time.Instant): Clock[cats.Id] = new Clock[cats.Id] {
    def instant: java.time.Instant = at
  }
}

trait Entropy[F[_]] {
  def bytes(n: Int): F[Array[Byte]]
}

object Entropy {
  def apply[F[_]](implicit entropy: Entropy[F]): Entropy[F] = entropy

  def hex(bytes: Array[Byte]): String = {
    val out = new StringBuilder(bytes.length * 2)
    bytes.foreach(b => out.append("%02x".format(b)))
    out.toString
  }
}
