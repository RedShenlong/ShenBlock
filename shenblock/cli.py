"""Punto de entrada y consola interactiva de ShenBlock."""

from __future__ import annotations

import argparse
import csv
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from rich.live import Live
from rich.prompt import Confirm, Prompt

from . import __version__
from .action import LaboratoryAction
from .monitor import BandwidthMonitor
from .oui import OuiResolver
from .scanner import NetworkScanner
from .spoofer import ARPSpoofer
from .system import IpForwarding
from .theme import make_console
from .ui import ShenUI


def build_parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        prog="shenblock",
        description="ShenBlock · inventario de red para laboratorios autorizados",
    )
    command.add_argument("--network", help="red IPv4 CIDR, por ejemplo 192.168.1.0/24")
    command.add_argument("--interface", help="interfaz de red, por ejemplo eth0")
    command.add_argument("--timeout", type=float, default=1.5, help="espera de respuestas ARP")
    command.add_argument("--manuf", help="ruta a un fichero OUI estilo 'manuf' para más fabricantes")
    command.add_argument("--no-hostname", action="store_true", help="no resolver nombres por DNS inverso")
    command.add_argument("--no-clear", action="store_true", help="no limpiar la pantalla al arrancar")
    command.add_argument("--version", action="version", version=f"ShenBlock {__version__}")
    return command


@dataclass
class Command:
    """Descripción de un comando de la consola."""

    handler: Callable[["Shell", str], None]
    usage: str
    help: str
    aliases: tuple[str, ...] = ()


class Shell:
    """Estado y bucle de la consola interactiva."""

    def __init__(
        self,
        scanner: NetworkScanner,
        network: str,
        resolve_hostname: bool = True,
        clear_on_start: bool = True,
    ) -> None:
        self.console = make_console()
        self.ui = ShenUI(self.console)
        self.scanner = scanner
        self.network = network
        self.resolve_hostname = resolve_hostname
        self.clear_on_start = clear_on_start
        self.devices: list = []
        self.action: LaboratoryAction | None = None
        self.monitor: BandwidthMonitor | None = None
        self._gateway: tuple[str, str] | None = None
        self._self_ip: str | None = None
        self._authorized = False
        self.registry: dict[str, Command] = {}
        self._register_commands()

    # --------------------------------------------------------- registro
    def _register_commands(self) -> None:
        commands = {
            "help": Command(Shell.cmd_help, "help", "muestra esta ayuda", ("?",)),
            "scan": Command(Shell.cmd_scan, "scan", "descubre equipos en la red local", ("rescan",)),
            "hosts": Command(Shell.cmd_hosts, "hosts", "muestra los hosts del último escaneo", ("list", "ls")),
            "info": Command(Shell.cmd_info, "info <n>", "detalle de un host por su número"),
            "block": Command(Shell.cmd_block, "block <sel>", "bloquea objetivos (p. ej. block 2,4 o block all)"),
            "free": Command(Shell.cmd_free, "free <sel>", "libera objetivos y restaura su ARP", ("unblock",)),
            "watch": Command(Shell.cmd_watch, "watch [sel]", "monitor de consumo en vivo (watch all para MITM)", ("mon", "top")),
            "limit": Command(Shell.cmd_limit, "limit <sel>", "límite de ancho de banda (pendiente de tc)"),
            "status": Command(Shell.cmd_status, "status", "muestra el estado del bloqueo activo", ("st",)),
            "export": Command(Shell.cmd_export, "export <archivo>", "guarda los hosts en .json o .csv"),
            "interfaces": Command(Shell.cmd_interfaces, "interfaces", "lista las interfaces disponibles", ("ifaces",)),
            "network": Command(Shell.cmd_network, "network <cidr>", "muestra o cambia la red objetivo", ("net",)),
            "clear": Command(Shell.cmd_clear, "clear", "limpia la pantalla", ("cls",)),
            "exit": Command(Shell.cmd_exit, "exit", "libera todo y cierra ShenBlock", ("quit", "q")),
        }
        for name, command in commands.items():
            self.registry[name] = command
            for alias in command.aliases:
                self.registry[alias] = command

    # ---------------------------------------------------------- comandos
    def cmd_help(self, _argument: str) -> None:
        self.console.print("[brand]Comandos disponibles[/]")
        seen: set[int] = set()
        for command in self.registry.values():
            if id(command) in seen:
                continue
            seen.add(id(command))
            aliases = f"  [muted](alias: {', '.join(command.aliases)})[/]" if command.aliases else ""
            self.console.print(f"  [key]{command.usage:<18}[/] {command.help}{aliases}")
        self.console.print(
            "\n[warn]![/] [muted]block redirige y descarta el tráfico de los objetivos. "
            "Úselo solo con autorización. 'exit' restaura la red.[/]"
        )

    def cmd_scan(self, _argument: str) -> None:
        try:
            self.scanner.validate_network(self.network)
        except (ValueError, OSError) as error:
            self.ui.error(f"Red inválida: {error}")
            return
        try:
            self.devices = self.ui.scan_with_progress(
                run_raw=lambda: self.scanner.scan_raw(self.network),
                run_enrich=lambda raw: self.scanner.enrich(
                    raw, resolve_hostname=self.resolve_hostname
                ),
                expected_seconds=self.scanner.timeout,
            )
        except (ValueError, OSError, PermissionError) as error:
            self.ui.error(f"Error de descubrimiento: {error}")
            return
        self.ui.ok(f"Escaneo terminado: {len(self.devices)} host(s). Escriba [key]hosts[/].")

    def cmd_hosts(self, _argument: str) -> None:
        self.ui.devices_table(
            self.devices,
            blocked=self._blocked_ips(),
            gateway_ip=self._gateway[0] if self._gateway else None,
            self_ip=self._self_ip,
        )

    def cmd_info(self, argument: str) -> None:
        if not self._require_devices():
            return
        try:
            index = int(argument.strip())
            if not 1 <= index <= len(self.devices):
                raise ValueError
        except ValueError:
            self.ui.error("indique un número de host válido, p. ej. info 1")
            return
        self.ui.device_detail(index, self.devices[index - 1])

    def cmd_block(self, argument: str) -> None:
        if not self._require_devices():
            return
        try:
            selected = self.ui.parse_selection(argument, self.devices)
        except ValueError as error:
            self.ui.error(str(error))
            return
        if not self._confirm_authorization(selected):
            self.ui.warn("Operación cancelada.")
            return
        action = self._ensure_action()
        if action is None:
            return
        try:
            active = action.block(selected)
        except (OSError, PermissionError) as error:
            self.ui.error(f"No se pudo iniciar el bloqueo: {error}")
            return
        self.ui.ok(
            f"Bloqueando {len(selected)} objetivo(s). Activos: {active}. "
            f"Use [key]free[/] para liberar."
        )

    def cmd_free(self, argument: str) -> None:
        if self.action is None or not self.action.running:
            self.ui.info("No hay ningún bloqueo activo.")
            return
        if argument.strip().lower() == "all":
            self.action.stop()
            self.ui.ok("Todos los objetivos liberados. Red restaurada.")
            return
        if not self._require_devices():
            return
        try:
            selected = self.ui.parse_selection(argument, self.devices)
        except ValueError as error:
            self.ui.error(str(error))
            return
        remaining = self.action.free(selected)
        self.ui.ok(f"Liberado(s) {len(selected)} objetivo(s). Activos: {remaining}.")

    def cmd_watch(self, argument: str) -> None:
        if not self._require_devices():
            return
        selection = argument.strip().lower()
        # Sin argumento (o 'all') => MITM de todos los equipos descubiertos,
        # que es lo que hace que el consumo de verdad aparezca.
        if selection in ("", "all"):
            mitm_targets: list = list(self.devices)
        else:
            try:
                mitm_targets = self.ui.parse_selection(argument, self.devices)
            except ValueError as error:
                self.ui.error(str(error))
                return

        block_active = self.action is not None and self.action.running and self.action.drop_traffic
        if block_active:
            self.ui.warn(
                "Hay un bloqueo activo (sin reenvío); mostrando solo el tráfico "
                "visible. Libere el bloqueo para medir con MITM."
            )
            mitm_targets = []
        elif mitm_targets and not self._confirm_authorization(mitm_targets):
            self.ui.warn("Operación cancelada.")
            return

        spoofer, forwarding, saved_forward = self._start_watch_mitm(mitm_targets)
        self._ensure_monitor()
        if self.monitor is None:
            self._stop_watch_mitm(spoofer, forwarding, saved_forward)
            return

        self.ui.info("Monitor en vivo (se actualiza solo). Ctrl+C para volver a la consola.")
        try:
            # screen=False => se dibuja en línea, bajo los comandos anteriores,
            # y se refresca en el sitio sin borrar el historial de la terminal.
            with Live(
                console=self.console,
                refresh_per_second=4,
                screen=False,
                transient=False,
            ) as live:
                while True:
                    live.update(
                        self.ui.bandwidth_dashboard(
                            self.devices,
                            self.monitor.rates_total(),
                            self._blocked_ips(),
                            gateway_ip=self._gateway[0] if self._gateway else None,
                            self_ip=self._self_ip,
                        )
                    )
                    time.sleep(0.25)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop_watch_mitm(spoofer, forwarding, saved_forward)
        self.ui.ok("Monitor detenido. Red restaurada.")

    def cmd_limit(self, _argument: str) -> None:
        self.ui.warn(
            "El límite de ancho de banda aún no está implementado: requiere "
            "configurar [key]tc/netem[/] sobre la ruta reenviada. Por ahora use "
            "[key]block[/] / [key]free[/]."
        )

    def cmd_status(self, _argument: str) -> None:
        if self.action is None or not self.action.running:
            self.ui.info("Sin bloqueo activo.")
            return
        status = self.action.refresh() or "sin datos"
        self.console.print(f"[brand]Estado[/]: {status}")
        for target in self.action.spoofer.targets():
            self.console.print(f"  [error]⛔[/] [device.ip]{target.ip}[/]  [device.mac]{target.mac}[/]")

    def cmd_export(self, argument: str) -> None:
        if not self._require_devices():
            return
        target = argument.strip()
        if not target:
            self.ui.error("indique un archivo, p. ej. export hosts.json")
            return
        try:
            path = self._export(target)
        except OSError as error:
            self.ui.error(f"no se pudo escribir: {error}")
            return
        self.ui.ok(f"Guardados {len(self.devices)} host(s) en [key]{path}[/].")

    def cmd_interfaces(self, _argument: str) -> None:
        interfaces = self.scanner.available_interfaces()
        active = self.scanner.interface
        self.console.print("[brand]Interfaces[/]")
        for name in interfaces:
            marker = "[ok]●[/]" if name == active else "[muted]○[/]"
            self.console.print(f"  {marker} {name}")

    def cmd_network(self, argument: str) -> None:
        new_value = argument.strip()
        if not new_value:
            self.ui.info(f"Red objetivo actual: [key]{self.network}[/]")
            return
        try:
            subnet = self.scanner.validate_network(new_value)
        except (ValueError, OSError) as error:
            self.ui.error(f"Red inválida: {error}")
            return
        self.network = str(subnet)
        self.devices = []
        self.ui.ok(f"Red objetivo cambiada a [key]{self.network}[/]. Ejecute [key]scan[/].")

    def cmd_clear(self, _argument: str) -> None:
        self.console.clear()
        self.ui.banner()

    def cmd_exit(self, _argument: str) -> None:
        raise _ExitShell

    # ----------------------------------------------------------- apoyo
    def _require_devices(self) -> bool:
        if not self.devices:
            self.ui.warn("Primero ejecute [key]scan[/].")
            return False
        return True

    def _blocked_ips(self) -> set[str]:
        if self.action is None or not self.action.running:
            return set()
        return {target.ip for target in self.action.spoofer.targets()}

    def _ensure_monitor(self) -> None:
        if self.monitor is None:
            self.monitor = BandwidthMonitor(self.scanner.interface)
        if not self.monitor.running:
            try:
                self.monitor.start()
            except (OSError, PermissionError) as error:
                self.ui.error(f"No se pudo iniciar el monitor: {error}")
                self.monitor = None

    def _start_watch_mitm(self, targets: list):
        """Arranca un MITM temporal (reenvío activo) para ver el consumo."""
        if not targets:
            return None, None, None
        action = self._ensure_action()
        if action is None:
            return None, None, None
        gateway_ip, gateway_mac = self._gateway  # type: ignore[misc]
        forwarding = IpForwarding()
        saved_forward = forwarding.read()
        forwarding.set(True)
        spoofer = ARPSpoofer(self.scanner.interface, gateway_ip, gateway_mac)
        for device in targets:
            spoofer.add(device.ip, device.mac)
        spoofer.start()
        self.ui.info(f"MITM activo sobre {len(targets)} equipo(s) (reenvío ON).")
        return spoofer, forwarding, saved_forward

    def _stop_watch_mitm(self, spoofer, forwarding, saved_forward) -> None:
        if spoofer is not None:
            spoofer.stop(restore=True)
        if forwarding is not None and saved_forward is not None:
            forwarding.set(saved_forward)

    def _confirm_authorization(self, selected: list) -> bool:
        """Pide confirmación explícita de autorización la primera vez."""
        if self._authorized:
            return True
        self.ui.warn(
            f"Va a redirigir y descartar el tráfico de {len(selected)} equipo(s) "
            f"en [key]{self.network}[/]."
        )
        confirmed = Confirm.ask(
            "[prompt]¿Confirma que tiene autorización expresa sobre esta red?[/]",
            default=False,
        )
        self._authorized = confirmed
        return confirmed

    def _ensure_action(self) -> LaboratoryAction | None:
        """Crea la acción resolviendo el gateway la primera vez."""
        if self.action is not None:
            return self.action
        try:
            if self._gateway is None:
                gateway_ip = self.scanner.gateway_ip()
                with self.console.status(f"[accent]Resolviendo gateway {gateway_ip}…[/]", spinner="dots"):
                    gateway_mac = self.scanner.resolve_mac(gateway_ip)
                self._gateway = (gateway_ip, gateway_mac)
            gateway_ip, gateway_mac = self._gateway
        except (OSError, PermissionError) as error:
            self.ui.error(f"No se pudo preparar la acción: {error}")
            return None
        self.action = LaboratoryAction(self.scanner.interface, gateway_ip, gateway_mac)
        self.ui.info(f"Gateway [key]{gateway_ip}[/] → [device.mac]{gateway_mac}[/]")
        return self.action

    def _export(self, target: str) -> Path:
        path = Path(target).expanduser()
        rows = [
            {
                "ip": device.ip,
                "mac": device.mac,
                "vendor": device.vendor or "",
                "hostname": device.hostname or "",
                "discovered_at": device.discovered_at.isoformat(),
            }
            for device in self.devices
        ]
        if path.suffix.lower() == ".csv":
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
        else:
            if path.suffix.lower() != ".json":
                path = path.with_suffix(".json")
            payload = {"network": self.network, "interface": self.scanner.interface, "hosts": rows}
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def _shutdown(self) -> None:
        """Restaura la red al cerrar, pase lo que pase."""
        if self.monitor is not None and self.monitor.running:
            self.monitor.stop()
        if self.action is not None and self.action.running:
            self.ui.info("Restaurando tablas ARP y reenvío IP…")
            self.action.stop()

    def _blocked_count(self) -> int:
        return self.action.active_count if self.action is not None else 0

    # ------------------------------------------------------------ bucle
    def run(self) -> None:
        if self.clear_on_start:
            self.console.clear()
        self.ui.banner()
        try:
            source_ip = self.scanner.source_ip()
            self._self_ip = source_ip
        except OSError:
            source_ip = "?"
        self.ui.session_header(self.scanner.interface, self.network, source_ip)
        self.cmd_help("")
        try:
            while True:
                prompt = self.ui.prompt_text(
                    self.network, self.scanner.interface, len(self.devices), self._blocked_count()
                )
                try:
                    raw = Prompt.ask(prompt).strip()
                except (EOFError, KeyboardInterrupt):
                    self.console.print()
                    break
                if not raw:
                    continue
                name, _, argument = raw.partition(" ")
                command = self.registry.get(name.lower())
                if command is None:
                    self.ui.warn(f"Comando desconocido: [key]{name}[/]. Use [key]help[/].")
                    continue
                try:
                    command.handler(self, argument)
                except _ExitShell:
                    break
        finally:
            self._shutdown()
            self.ui.ok("ShenBlock cerrado.")


class _ExitShell(Exception):
    """Señal interna para salir del bucle de la consola."""


def main() -> None:
    args = build_parser().parse_args()
    console = make_console()
    oui = OuiResolver.from_manuf_file(args.manuf) if args.manuf else OuiResolver()
    try:
        scanner = NetworkScanner(args.interface, args.timeout, oui=oui)
        network = args.network or str(scanner.default_network())
    except (OSError, ValueError) as error:
        console.print(f"[error]✗ No se pudo inicializar:[/] {error}")
        console.print("[muted]Pista: ejecute con privilegios y/o indique --interface y --network.[/]")
        raise SystemExit(1)
    Shell(
        scanner,
        network,
        resolve_hostname=not args.no_hostname,
        clear_on_start=not args.no_clear,
    ).run()


if __name__ == "__main__":
    main()
