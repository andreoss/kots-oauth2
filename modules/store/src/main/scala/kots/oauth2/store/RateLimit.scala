package kots.oauth2.store

trait RateLimiter[F[_]] {
  def acquire(key: String): F[Option[Long]]
}
