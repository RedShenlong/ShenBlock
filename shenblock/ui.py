"""Capa de presentación: banner, tablas y paneles con Rich."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from . import __version__
from .models import Device, SessionPlan
from .theme import make_console

# Logotipo en bloque (fuente estilo "ANSI Shadow"), partido en dos palabras
# para que entre bien incluso en terminales estrechas.
_SHEN = [
    "███████╗██╗  ██╗███████╗███╗   ██╗",
    "██╔════╝██║  ██║██╔════╝████╗  ██║",
    "███████╗███████║█████╗  ██╔██╗ ██║",
    "╚════██║██╔══██║██╔══╝  ██║╚██╗██║",
    "███████║██║  ██║███████╗██║ ╚████║",
    "╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝",
]
_BLOCK = [
    "██████╗ ██╗      ██████╗  ██████╗██╗  ██╗",
    "██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝",
    "██████╔╝██║     ██║   ██║██║     █████╔╝ ",
    "██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ",
    "██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗",
    "╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝",
]

# Degradado cian -> magenta aplicado por filas al logotipo.
_GRADIENT = ["#22d3ee", "#38bdf8", "#818cf8", "#a78bfa", "#c084fc", "#e879f9"]


class ShenUI:
    """Dibuja todo lo que ve el usuario."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or make_console()

    # ------------------------------------------------------------- banner
    def banner(self) -> None:
        """Muestra el logotipo con degradado y una cabecera informativa."""
        logo = Text(justify="left")
        for index, line in enumerate(_SHEN):
            logo.append(line + "\n", style=_GRADIENT[index % len(_GRADIENT)])
        for index, line in enumerate(_BLOCK):
            logo.append(line + "\n", style=_GRADIENT[index % len(_GRADIENT)])
        subtitle = Text(
            "INVENTARIO DE RED  ·  MODO LABORATORIO  ·  SOLO RESPUESTAS ARP",
            style="muted",
        )
        version = Text(f"v{__version__}", style="accent.alt")
        self.console.print()
        self.console.print(Align.left(Group(logo, subtitle, version)))
        self.console.print()

    def session_header(self, interface: str, network: str, source_ip: str) -> None:
        """Panel compacto con la interfaz, la IP local y la red objetivo."""
        body = Text.assemble(
            ("Interfaz  ", "muted"), (f"{interface}\n", "key"),
            ("IP local  ", "muted"), (f"{source_ip}\n", "value"),
            ("Red       ", "muted"), (f"{network}", "device.ip"),
        )
        self.console.print(
            Panel(body, title="[brand]ShenBlock[/]", border_style="accent", box=box.ROUNDED, expand=False)
        )

    # ----------------------------------------------------- formateo
    @staticmethod
    def human_rate(bps: float) -> str:
        """Convierte bytes/s en una cadena legible (B/s, KB/s, MB/s…)."""
        value = float(bps)
        for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
            if value < 1024 or unit == "GB/s":
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} GB/s"

    @staticmethod
    def rate_bar(bps: float, peak: float, width: int = 12) -> str:
        """Barra de bloques proporcional a ``bps`` respecto a ``peak``."""
        fraction = 0.0 if peak <= 0 else min(1.0, bps / peak)
        filled = int(round(fraction * width))
        color = "magenta" if fraction > 0.66 else "cyan" if fraction > 0.33 else "accent"
        return f"[{color}]{'█' * filled}[/][muted]{'░' * (width - filled)}[/]"

    @staticmethod
    def is_random_mac(mac: str) -> bool:
        """``True`` si el MAC es localmente administrado (privado/aleatorio).

        Los móviles modernos (iPhone, Android) usan MAC aleatoria por privacidad:
        el segundo bit menos significativo del primer octeto está a 1. Esas
        direcciones no pertenecen a ningún fabricante real.
        """
        try:
            first_octet = int(mac.split(":")[0], 16)
        except (ValueError, IndexError):
            return False
        return bool(first_octet & 0b10)

    def vendor_cell(self, device: Device) -> str:
        """Texto de la columna Fabricante, con aviso de MAC privada."""
        if device.vendor:
            return device.vendor
        if self.is_random_mac(device.mac):
            return "[muted](MAC privada)[/]"
        return "[muted]—[/]"

    def _label_for(self, device: Device, gateway_ip: str | None, self_ip: str | None) -> str:
        if device.hostname:
            return device.hostname
        if gateway_ip and device.ip == gateway_ip:
            return "[accent](gateway)[/]"
        if self_ip and device.ip == self_ip:
            return "[accent](este equipo)[/]"
        if self.is_random_mac(device.mac):
            return "[muted](móvil?)[/]"
        return "[muted]—[/]"

    # ------------------------------------------------------------- tablas
    def devices_table(
        self,
        devices: list[Device],
        *,
        blocked: set[str] | None = None,
        gateway_ip: str | None = None,
        self_ip: str | None = None,
    ) -> None:
        """Tabla de hosts con fabricante, nombre y estado.

        El consumo no se muestra aquí: solo es fiable mientras se redirige el
        tráfico, así que vive en el monitor en vivo (``watch``).
        """
        if not devices:
            self.info("Aún no hay resultados. Ejecute [key]scan[/].")
            return
        blocked = blocked or set()
        table = Table(
            title=f"Hosts detectados ({len(devices)})",
            box=box.SIMPLE_HEAVY,
            header_style="table.header",
            expand=False,
            pad_edge=False,
        )
        table.add_column("#", justify="right", style="device.id")
        table.add_column("IPv4", style="device.ip", no_wrap=True)
        table.add_column("MAC", style="device.mac", no_wrap=True)
        table.add_column("Fabricante", style="device.vendor")
        table.add_column("Nombre", style="device.host")
        table.add_column("Estado", no_wrap=True)
        for index, device in enumerate(devices, start=1):
            state = "[error]🔒 block[/]" if device.ip in blocked else "[ok]✓ libre[/]"
            table.add_row(
                str(index),
                device.ip,
                device.mac,
                self.vendor_cell(device),
                self._label_for(device, gateway_ip, self_ip),
                state,
            )
        self.console.print(table)

    def device_detail(self, index: int, device: Device) -> None:
        """Ficha detallada de un único host."""
        body = Text.assemble(
            ("ID         ", "muted"), (f"{index}\n", "device.id"),
            ("IPv4       ", "muted"), (f"{device.ip}\n", "device.ip"),
            ("MAC        ", "muted"), (f"{device.mac}\n", "device.mac"),
            ("Fabricante ", "muted"), (f"{device.vendor or ('MAC privada' if self.is_random_mac(device.mac) else '—')}\n", "device.vendor"),
            ("Nombre     ", "muted"), (f"{device.hostname or '—'}\n", "device.host"),
            ("Visto (UTC)", "muted"), (f" {device.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}", "device.time"),
        )
        self.console.print(
            Panel(body, title=f"[brand]Host {device.ip}[/]", border_style="accent", box=box.ROUNDED, expand=False)
        )

    # ---------------------------------------------------- dashboard
    def bandwidth_dashboard(
        self,
        devices: list[Device],
        rates: dict[str, float],
        blocked: set[str],
        *,
        gateway_ip: str | None = None,
        self_ip: str | None = None,
    ) -> Table:
        """Tabla en vivo (para ``Live``) con barras de consumo por dispositivo."""
        peak = max(rates.values(), default=0.0)
        total = sum(rates.values())
        ordered = sorted(devices, key=lambda d: rates.get(d.ip, 0.0), reverse=True)
        table = Table(
            title=f"ShenBlock · monitor en vivo  [muted](total {self.human_rate(total)})[/]",
            box=box.SIMPLE_HEAVY,
            header_style="table.header",
            caption="[muted]Ctrl+C para salir del monitor[/]",
            expand=False,
            pad_edge=False,
        )
        table.add_column("IPv4", style="device.ip", no_wrap=True)
        table.add_column("Dispositivo", style="device.vendor")
        table.add_column("Estado", no_wrap=True)
        table.add_column("Consumo", justify="right", no_wrap=True)
        table.add_column("", no_wrap=True)  # barra
        for device in ordered:
            bps = rates.get(device.ip, 0.0)
            name = device.hostname or self._label_for(device, gateway_ip, self_ip)
            if name in ("[muted]—[/]", "[muted](móvil?)[/]"):
                name = self.vendor_cell(device)
            state = "[error]🔒[/]" if device.ip in blocked else "[ok]✓[/]"
            usage_style = "magenta" if bps >= peak > 0 else "device.vendor"
            table.add_row(
                device.ip,
                name,
                state,
                f"[{usage_style}]{self.human_rate(bps)}[/]",
                self.rate_bar(bps, peak, width=22),
            )
        return table

    def session_panel(self, plan: SessionPlan, remaining: int, status: str | None = None) -> Panel:
        """Panel en vivo para el temporizador de una sesión de laboratorio."""
        targets = ", ".join(device.ip for device in plan.targets[:6])
        if plan.target_count > 6:
            targets += f"  (+{plan.target_count - 6})"
        lines = Text.assemble(
            ("Ejercicio  ", "muted"), (f"{plan.label}\n", "key"),
            ("Objetivos  ", "muted"), (f"{plan.target_count}\n", "value"),
            ("Equipos    ", "muted"), (f"{targets}\n", "device.ip"),
            ("Restante   ", "muted"), (f"{remaining}s\n\n", "warn"),
        )
        if status:
            lines.append(status + "\n\n", style="accent")
        lines.append("La red NO se modifica: el módulo de acción sigue vacío.\n", style="muted")
        lines.append("Ctrl+C para volver a la consola.", style="muted")
        return Panel(lines, title="[brand.alt]SESIÓN DE LABORATORIO[/]", border_style="accent.alt", box=box.HEAVY, expand=False)

    # ---------------------------------------------------------- prompt
    def prompt_text(self, network: str, interface: str, hosts: int, blocked: int) -> str:
        """Prompt de consola de dos líneas con estilo 'tecnológico'."""
        status = f"[error]⛔ {blocked}[/]" if blocked else "[ok]●[/]"
        return (
            f"[accent]╭─[/]{status}[accent]─[/][brand] shenblock[/] "
            f"[muted]·[/] [key]{interface}[/] "
            f"[muted]·[/] [device.ip]{network}[/] "
            f"[muted]·[/] [device.vendor]{hosts} host(s)[/]\n"
            f"[accent]╰─▸[/] "
        )

    # ------------------------------------------------------ escaneo "wow"
    def scan_with_progress(
        self,
        run_raw: Callable[[], list[Device]],
        run_enrich: Callable[[list[Device]], list[Device]],
        expected_seconds: float,
    ) -> list[Device]:
        """Escaneo con barra de progreso por fases (ARP + enriquecimiento).

        ``run_raw`` y ``run_enrich`` se ejecutan en hilos para que la barra
        avance con fluidez; las excepciones se re-lanzan al llamante.
        """
        progress = Progress(
            SpinnerColumn(spinner_name="dots", style="accent"),
            TextColumn("[accent]{task.description}"),
            BarColumn(bar_width=38, complete_style="cyan", finished_style="magenta", pulse_style="accent.alt"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )
        with progress:
            raw = self._phase(
                progress, "Emitiendo sondas ARP", run_raw, expected_seconds
            )
            devices = self._phase(
                progress,
                f"Resolviendo {len(raw)} host(s)",
                lambda: run_enrich(raw),
                max(0.4, len(raw) * 0.05),
            )
        return devices

    @staticmethod
    def _phase(progress: Progress, description: str, work: Callable[[], object], expected: float):
        """Ejecuta ``work`` en un hilo mientras la barra se llena hasta el 95 %."""
        box: dict[str, object] = {}

        def runner() -> None:
            try:
                box["result"] = work()
            except BaseException as error:  # noqa: BLE001 - se re-lanza abajo
                box["error"] = error

        task = progress.add_task(description, total=100)
        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        start = time.monotonic()
        while thread.is_alive():
            fraction = min(0.95, (time.monotonic() - start) / max(0.1, expected))
            progress.update(task, completed=fraction * 100)
            time.sleep(0.05)
        thread.join()
        progress.update(task, completed=100)
        if "error" in box:
            raise box["error"]  # type: ignore[misc]
        return box.get("result")

    # -------------------------------------------------------- mensajería
    def info(self, message: str) -> None:
        self.console.print(f"[accent]›[/] {message}")

    def ok(self, message: str) -> None:
        self.console.print(f"[ok]✓[/] {message}")

    def warn(self, message: str) -> None:
        self.console.print(f"[warn]![/] {message}")

    def error(self, message: str) -> None:
        self.console.print(f"[error]✗ {message}[/]")

    # --------------------------------------------------------- selección
    @staticmethod
    def parse_selection(raw: str, devices: list[Device]) -> list[Device]:
        """Convierte `all`, `1,3-5` o `1, 3, 5` en una lista de dispositivos."""
        if raw.strip().lower() == "all":
            return devices[:]
        if not raw.strip():
            raise ValueError("indique objetivos, p. ej. 1,3-5 o all")
        chosen: set[int] = set()
        try:
            for part in raw.replace(" ", "").split(","):
                if not part:
                    continue
                bounds = part.split("-", 1)
                start = int(bounds[0])
                end = int(bounds[-1])
                if start > end:
                    start, end = end, start
                chosen.update(range(start, end + 1))
        except ValueError as error:
            raise ValueError("selección inválida") from error
        if not chosen or min(chosen) < 1 or max(chosen) > len(devices):
            raise ValueError("hay índices fuera de la tabla")
        return [devices[index - 1] for index in sorted(chosen)]
