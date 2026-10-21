"""Acción de red del laboratorio: orquesta el envenenamiento ARP.

Esta clase es la que ``cli`` usa para llevar a cabo un ejercicio. Mantiene el
contrato histórico (``run`` / ``refresh`` / ``stop``) y añade ``block`` / ``free``
para el modelo persistente estilo *evillimiter*: los objetivos se bloquean y se
liberan en caliente mientras la consola sigue abierta.

ADVERTENCIA: bloquear redirige (y descarta) el tráfico de los equipos objetivo.
Úsese solo en redes propias o con autorización expresa. ``stop`` restaura
siempre las tablas ARP y el estado de reenvío IP.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import Device, SessionPlan
from .spoofer import ARPSpoofer
from .system import IpForwarding


class LaboratoryAction:
    """Coordina el :class:`ARPSpoofer` y el reenvío IP de forma segura."""

    def __init__(
        self,
        interface: str,
        gateway_ip: str,
        gateway_mac: str,
        *,
        interval: float = 2.0,
        drop_traffic: bool = True,
    ) -> None:
        self.spoofer = ARPSpoofer(interface, gateway_ip, gateway_mac, interval)
        self._forwarding = IpForwarding()
        self._saved_forwarding: bool | None = None
        #: Si es ``True``, el bloqueo desactiva el reenvío IP para descartar el
        #: tráfico de la víctima (bloqueo real). Si es ``False``, el tráfico
        #: pasa por esta máquina (MITM), base para un futuro límite con ``tc``.
        self.drop_traffic = drop_traffic

    # ------------------------------------------------- contrato clásico
    def run(self, plan: SessionPlan) -> None:
        """Arranca un ejercicio a partir de un :class:`SessionPlan`."""
        self.block(plan.targets)

    def refresh(self) -> str | None:
        """Texto de estado para la interfaz, o ``None`` si no hay actividad."""
        targets = self.spoofer.targets()
        if not targets:
            return None
        forwarding = self._forwarding.read()
        mode = "bloqueando (sin reenvío)" if self.drop_traffic else "MITM (reenvío activo)"
        if forwarding is not None:
            mode += f" · ip_forward={'1' if forwarding else '0'}"
        return f"{len(targets)} objetivo(s) · {mode}"

    def stop(self) -> None:
        """Detiene todo y restaura la red (ARP + reenvío IP)."""
        self.spoofer.stop(restore=True)
        self._restore_forwarding()

    # -------------------------------------------------- modelo persistente
    def block(self, devices: Iterable[Device]) -> int:
        """Añade objetivos al bloqueo y arranca el spoofer si hace falta."""
        devices = list(devices)
        if not devices:
            return len(self.spoofer.targets())
        if self.drop_traffic and not self.spoofer.running:
            # Guardar el estado original de reenvío solo la primera vez.
            self._saved_forwarding = self._forwarding.read()
            self._forwarding.set(False)
        for device in devices:
            self.spoofer.add(device.ip, device.mac)
        self.spoofer.start()
        return len(self.spoofer.targets())

    def free(self, devices: Iterable[Device]) -> int:
        """Libera objetivos (restaura su ARP). Devuelve los que quedan activos."""
        for device in devices:
            self.spoofer.remove(device.ip, restore=True)
        remaining = self.spoofer.targets()
        if not remaining:
            self.stop()
        return len(remaining)

    @property
    def active_count(self) -> int:
        return len(self.spoofer.targets())

    @property
    def running(self) -> bool:
        return self.spoofer.running

    def _restore_forwarding(self) -> None:
        if self._saved_forwarding is not None:
            self._forwarding.set(self._saved_forwarding)
            self._saved_forwarding = None
