"""Monitor de ancho de banda por dispositivo.

Escucha la interfaz y contabiliza los bytes IP que entran y salen de cada
dirección, calculando una tasa (bytes/s) en una ventana corta. Solo mide el
tráfico que *llega a nuestra tarjeta*: en una red conmutada eso es nuestro
propio tráfico, el de difusión y el de los equipos cuyo tráfico estemos
redirigiendo (MITM). Combinado con el envenenamiento ARP con reenvío activo,
permite ver el consumo de los objetivos en tiempo real.
"""

from __future__ import annotations

import threading
import time

from scapy.all import IP, AsyncSniffer  # type: ignore[import-untyped]


class BandwidthMonitor:
    """Contabiliza bytes por IP y expone su tasa instantánea."""

    def __init__(self, interface: str, sample_interval: float = 1.0) -> None:
        if sample_interval <= 0:
            raise ValueError("sample_interval debe ser positivo")
        self.interface = interface
        self.sample_interval = sample_interval

        self._lock = threading.Lock()
        self._totals: dict[str, list[int]] = {}       # ip -> [subida, bajada] acumulado
        self._rates: dict[str, tuple[float, float]] = {}  # ip -> (subida_bps, bajada_bps)
        self._last: dict[str, tuple[int, int]] = {}
        self._last_time = time.monotonic()

        self._sniffer: AsyncSniffer | None = None
        self._sampler: threading.Thread | None = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    # ------------------------------------------------------- control
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._last_time = time.monotonic()
        self._sniffer = AsyncSniffer(
            iface=self.interface, filter="ip", store=False, prn=self._on_packet
        )
        self._sniffer.start()
        self._sampler = threading.Thread(target=self._sample_loop, name="bw-sampler", daemon=True)
        self._sampler.start()

    def stop(self) -> None:
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001 - parar un sniffer ya detenido no debe fallar
                pass
            self._sniffer = None
        sampler = self._sampler
        if sampler is not None and sampler.is_alive():
            sampler.join(timeout=self.sample_interval + 0.5)
        self._sampler = None

    # ----------------------------------------------------- contadores
    def _on_packet(self, packet) -> None:
        if IP not in packet:
            return
        size = len(packet)
        src = packet[IP].src
        dst = packet[IP].dst
        with self._lock:
            self._totals.setdefault(src, [0, 0])[0] += size  # el origen "sube"
            self._totals.setdefault(dst, [0, 0])[1] += size  # el destino "baja"

    def _sample_loop(self) -> None:
        while self._running:
            time.sleep(self.sample_interval)
            self._compute_rates()

    def _compute_rates(self) -> None:
        now = time.monotonic()
        with self._lock:
            snapshot = {ip: (vals[0], vals[1]) for ip, vals in self._totals.items()}
            dt = max(1e-3, now - self._last_time)
            rates: dict[str, tuple[float, float]] = {}
            for ip, (up, down) in snapshot.items():
                prev_up, prev_down = self._last.get(ip, (0, 0))
                rates[ip] = ((up - prev_up) / dt, (down - prev_down) / dt)
            self._rates = rates
            self._last = snapshot
            self._last_time = now

    # -------------------------------------------------------- lectura
    def rates(self) -> dict[str, tuple[float, float]]:
        """Copia de las tasas por IP: ``{ip: (subida_bps, bajada_bps)}``."""
        with self._lock:
            return dict(self._rates)

    def total_bps(self, ip: str) -> float:
        """Tasa combinada (subida + bajada) de una IP, en bytes/s."""
        up, down = self.rates().get(ip, (0.0, 0.0))
        return up + down

    def rates_total(self) -> dict[str, float]:
        """Tasa combinada por IP: ``{ip: subida+bajada}`` en bytes/s."""
        return {ip: up + down for ip, (up, down) in self.rates().items()}
