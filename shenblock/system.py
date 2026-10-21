"""Utilidades del sistema operativo (Linux) para la acción de red.

Por ahora solo gestiona el reenvío de IPv4 (``net.ipv4.ip_forward``). Se usa
para que un bloqueo real descarte el tráfico de la víctima en lugar de
reenviarlo. Todas las operaciones degradan de forma segura si el fichero no
está disponible o no hay privilegios.
"""

from __future__ import annotations

from pathlib import Path


class IpForwarding:
    """Lee y escribe ``/proc/sys/net/ipv4/ip_forward`` de forma tolerante."""

    PATH = Path("/proc/sys/net/ipv4/ip_forward")

    def available(self) -> bool:
        return self.PATH.exists()

    def read(self) -> bool | None:
        """Devuelve ``True``/``False`` según el estado, o ``None`` si no se puede leer."""
        try:
            return self.PATH.read_text().strip() == "1"
        except OSError:
            return None

    def set(self, enabled: bool) -> bool:
        """Activa o desactiva el reenvío. Devuelve ``True`` si lo consiguió."""
        try:
            self.PATH.write_text("1\n" if enabled else "0\n")
            return True
        except OSError:
            return False
