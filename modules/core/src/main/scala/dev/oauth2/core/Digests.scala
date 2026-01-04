package dev.oauth2.core

import java.nio.charset.StandardCharsets

private[core] object Digests {

  def sha256Hex(value: String): String =
    Entropy.hex(
      java.security.MessageDigest
        .getInstance("SHA-256")
        .digest(value.getBytes(StandardCharsets.US_ASCII))
    )

  def equal(one: String, other: String): Boolean =
    java.security.MessageDigest.isEqual(
      one.getBytes(StandardCharsets.US_ASCII),
      other.getBytes(StandardCharsets.US_ASCII)
    )
}
