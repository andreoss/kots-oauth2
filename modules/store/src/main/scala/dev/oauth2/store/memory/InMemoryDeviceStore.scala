package dev.oauth2.store.memory

import cats.Monad
import cats.effect.kernel.Ref
import cats.syntax.flatMap._
import cats.syntax.functor._

import dev.oauth2.core.Clock
import dev.oauth2.core.DeviceCode
import dev.oauth2.core.Subject
import dev.oauth2.core.UserCode
import dev.oauth2.store.DeviceRecord
import dev.oauth2.store.DeviceStore

final class InMemoryDeviceStore[F[_]: Monad] private (
    state: Ref[F, Map[DeviceCode, DeviceRecord]],
    clock: Clock[F]
) extends DeviceStore[F] {

  def save(record: DeviceRecord): F[Unit] =
    state.update(_.updated(record.deviceCode, record))

  def approve(userCode: UserCode, subject: Subject): F[Boolean] =
    decide(userCode, record => record.copy(subject = Some(subject)))

  def deny(userCode: UserCode): F[Boolean] =
    decide(userCode, record => record.copy(denied = true))

  def poll(deviceCode: DeviceCode): F[Option[DeviceRecord]] =
    clock.instant.flatMap { now =>
      state.modify { devices =>
        devices.get(deviceCode) match {
          case Some(record) =>
            (devices.updated(deviceCode, record.copy(lastPolledAt = Some(now))), Some(record))
          case None => (devices, None)
        }
      }
    }

  def consume(deviceCode: DeviceCode): F[Option[DeviceRecord]] =
    clock.instant.flatMap { now =>
      state.modify { devices =>
        devices.get(deviceCode) match {
          case Some(record) if !record.isExpired(now) => (devices - deviceCode, Some(record))
          case Some(_)                                => (devices - deviceCode, None)
          case None                                   => (devices, None)
        }
      }
    }

  private def decide(userCode: UserCode, transition: DeviceRecord => DeviceRecord): F[Boolean] =
    clock.instant.flatMap { now =>
      state.modify { devices =>
        devices.collectFirst {
          case (code, record) if record.userCode == userCode && !record.decided && !record.isExpired(now) =>
            (code, record)
        } match {
          case Some((code, record)) => (devices.updated(code, transition(record)), true)
          case None                 => (devices, false)
        }
      }
    }
}

object InMemoryDeviceStore {

  def create[F[_]: cats.effect.Sync](clock: Clock[F]): F[InMemoryDeviceStore[F]] =
    Ref.of[F, Map[DeviceCode, DeviceRecord]](Map.empty).map(state => new InMemoryDeviceStore(state, clock))
}
