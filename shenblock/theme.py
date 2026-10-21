"""Tema visual compartido para toda la aplicación.

Centraliza colores y estilos para que la interfaz se vea coherente y permita
cambiar la paleta en un único sitio.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

#: Paleta "tecnológica" cian/magenta sobre fondo oscuro.
SHEN_THEME = Theme(
    {
        "brand": "bold cyan",
        "brand.alt": "bold magenta",
        "accent": "cyan",
        "accent.alt": "magenta",
        "ok": "bold green",
        "warn": "bold yellow",
        "error": "bold red",
        "muted": "dim",
        "prompt": "bold magenta",
        "key": "bold cyan",
        "value": "white",
        "table.header": "bold cyan",
        "device.id": "magenta",
        "device.ip": "bright_green",
        "device.mac": "yellow",
        "device.vendor": "cyan",
        "device.host": "bright_white",
        "device.time": "dim",
    }
)


def make_console() -> Console:
    """Crea la consola de Rich con el tema de ShenBlock aplicado."""
    return Console(theme=SHEN_THEME, highlight=False)
