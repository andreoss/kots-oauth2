package dev.oauth2.core

import java.time.Instant

final class TestClock(start: Instant, step: java.time.Duration) extends Clock[cats.Id] {
  private var ticks: Long = 0L

  def instant: Instant = start.plus(step.multipliedBy(ticks))

  def advance(n: Long = 1L): Unit = ticks += n
}

final class TestEntropy(seed: Byte) extends Entropy[cats.Id] {
  private var calls: Long = 0L

  def bytes(n: Int): Array[Byte] = {
    val out = Array.fill(n)((seed + calls.toByte).toByte)
    calls += 1L
    out
  }
}
