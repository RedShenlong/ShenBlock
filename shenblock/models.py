"""Modelos de datos inmutables usados en toda la aplicación."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class Device:
    """Un host que respondió a una solicitud ARP local.

    Los campos ``vendor`` y ``hostname`` son enriquecimientos opcionales que se
    resuelven localmente (prefijo OUI del MAC y DNS inverso) después del
    descubrimiento; nunca implican capturar tráfico de terceros.
    """

    ip: str
    mac: str
    discovered_at: datetime
    vendor: str | None = None
    hostname: str | None = None

    def with_enrichment(self, *, vendor: str | None = None, hostname: str | None = None) -> "Device":
        """Devuelve una copia con el fabricante y/o el nombre de host añadidos."""
        return dataclasses.replace(
            self,
            vendor=vendor if vendor is not None else self.vendor,
            hostname=hostname if hostname is not None else self.hostname,
        )


@dataclass(frozen=True, slots=True)
class SessionPlan:
    """Selección de laboratorio; describe *qué* y *cuánto*, nunca *cómo*.

    Es la estructura que ``cli`` entrega al módulo de acción (vacío). Define los
    objetivos y la duración de un ejercicio, pero no realiza ningún cambio en la
    red por sí misma.
    """

    targets: tuple[Device, ...]
    duration_seconds: int
    #: Etiqueta libre para distinguir el tipo de ejercicio (p. ej. "block").
    label: str = "session"
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def target_count(self) -> int:
        return len(self.targets)
