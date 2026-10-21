"""Descubrimiento ARP nativo y enriquecimiento local de los resultados.

El escaneo envía una ráfaga ARP *broadcast* y procesa únicamente las respuestas
que llegan: no activa modo promiscuo ni captura tráfico de tránsito. El
enriquecimiento (fabricante por OUI y nombre por DNS inverso) se resuelve en
local a partir de datos que el propio host anuncia.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from scapy.all import ARP, Ether, conf, get_if_addr, srp  # type: ignore[import-untyped]

from .models import Device
from .oui import OuiResolver

#: Límite de seguridad: evita barrer redes enormes por accidente.
MAX_NETWORK_ADDRESSES = 4096


class NetworkScanner:
    """Envía una ráfaga ARP broadcast y procesa solamente sus respuestas."""

    def __init__(
        self,
        interface: str | None = None,
        timeout: float = 1.5,
        inter: float = 0.002,
        oui: OuiResolver | None = None,
    ) -> None:
        if timeout <= 0 or inter < 0:
            raise ValueError("timeout debe ser positivo e inter no puede ser negativo")
        self.interface = interface or self.default_interface()
        self.timeout = timeout
        self.inter = inter
        self.oui = oui or OuiResolver()

    # ------------------------------------------------------------------ red
    @staticmethod
    def available_interfaces() -> list[str]:
        """Lista las interfaces que Scapy conoce en este equipo."""
        return sorted(conf.ifaces.data)

    @staticmethod
    def default_interface() -> str:
        """Prefiere wlan0 y, si no existe, usa la interfaz de la ruta por defecto."""
        interfaces = set(conf.ifaces.data)
        if "wlan0" in interfaces:
            return "wlan0"
        interface, _source_ip, _gateway = conf.route.route("0.0.0.0")
        if not interface:
            raise OSError("no se detectó una interfaz con salida; use --interface")
        return interface

    def source_ip(self) -> str:
        """IP IPv4 asignada a la interfaz activa."""
        return get_if_addr(self.interface)

    def default_network(self) -> ipaddress.IPv4Network:
        """Deriva la subred conectada a la interfaz elegida."""
        source = ipaddress.IPv4Address(self.source_ip())
        # Cada ruta contiene: red, máscara, gateway, interfaz, dirección, métrica.
        # Elegimos la ruta conectada que contiene la IP origen de la interfaz.
        candidates: list[ipaddress.IPv4Network] = []
        for route_network, route_mask, _gw, iface, _addr, _metric in conf.route.routes:
            if iface != self.interface:
                continue
            # Scapy almacena las máscaras de ruta Linux como enteros de 32 bits
            # (por ejemplo, 4294967040 para /24). ``ipaddress`` las interpreta
            # como una longitud de prefijo, así que hay que convertirlas primero
            # a su representación IPv4 punteada.
            netmask = (
                str(ipaddress.IPv4Address(route_mask))
                if isinstance(route_mask, int)
                else route_mask
            )
            candidate = ipaddress.IPv4Network((route_network, netmask), strict=False)
            if source in candidate and candidate.prefixlen < 32:
                candidates.append(candidate)
        if not candidates:
            raise OSError("no se pudo determinar la red; indique --network CIDR")
        return max(candidates, key=lambda candidate: candidate.prefixlen)

    # -------------------------------------------------------------- escaneo
    @staticmethod
    def validate_network(network: str) -> ipaddress.IPv4Network:
        """Valida un CIDR IPv4 y aplica el límite de tamaño."""
        subnet = ipaddress.ip_network(network, strict=False)
        if not isinstance(subnet, ipaddress.IPv4Network):
            raise ValueError("solo se admite IPv4")
        if subnet.num_addresses > MAX_NETWORK_ADDRESSES:
            raise ValueError(
                f"red demasiado grande; use hasta {MAX_NETWORK_ADDRESSES} direcciones"
            )
        return subnet

    def scan_raw(self, network: str) -> list[Device]:
        """Emite la ráfaga ARP y devuelve los hosts SIN enriquecer.

        Separar esta fase del enriquecimiento permite a la interfaz mostrar una
        barra de progreso por etapas.
        """
        subnet = self.validate_network(network)

        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))
        answered, _ = srp(
            packet,
            iface=self.interface,
            timeout=self.timeout,
            inter=self.inter,
            verbose=False,
            retry=0,
        )
        now = datetime.now(timezone.utc)
        found = {
            reply.psrc: Device(reply.psrc, reply.hwsrc.lower(), now)
            for _, reply in answered
        }
        return sorted(found.values(), key=lambda device: ipaddress.ip_address(device.ip))

    def discover(
        self,
        network: str,
        *,
        resolve_vendor: bool = True,
        resolve_hostname: bool = True,
    ) -> list[Device]:
        """Descubre IP/MAC de *network* usando ARP, sin modo promiscuo.

        Tras recibir las respuestas, enriquece cada host en local con su
        fabricante (prefijo OUI) y su nombre (DNS inverso) si se solicita.
        """
        devices = self.scan_raw(network)
        if resolve_vendor or resolve_hostname:
            devices = self.enrich(
                devices, resolve_vendor=resolve_vendor, resolve_hostname=resolve_hostname
            )
        return devices

    # --------------------------------------------------------- gateway
    def gateway_ip(self) -> str:
        """IP del gateway por defecto que sale por la interfaz activa."""
        _iface, _src, gateway = conf.route.route("0.0.0.0")
        if not gateway or gateway == "0.0.0.0":
            raise OSError("no se pudo determinar el gateway por defecto")
        return gateway

    def resolve_mac(self, ip: str, timeout: float = 2.0) -> str:
        """Resuelve el MAC de una IP mediante una única solicitud ARP."""
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(
            packet, iface=self.interface, timeout=timeout, verbose=False, retry=1
        )
        for _sent, reply in answered:
            return reply.hwsrc.lower()
        raise OSError(f"sin respuesta ARP de {ip}; ¿está en la red?")

    def enrich(
        self,
        devices: list[Device],
        *,
        resolve_vendor: bool = True,
        resolve_hostname: bool = True,
    ) -> list[Device]:
        """Añade fabricante y nombre de host a cada dispositivo (en local)."""
        if not devices:
            return devices

        hostnames: dict[str, str | None] = {}
        if resolve_hostname:
            hostnames = self._resolve_hostnames([device.ip for device in devices])

        enriched: list[Device] = []
        for device in devices:
            vendor = self.oui.lookup(device.mac) if resolve_vendor else None
            hostname = hostnames.get(device.ip) if resolve_hostname else None
            enriched.append(device.with_enrichment(vendor=vendor, hostname=hostname))
        return enriched

    @staticmethod
    def _resolve_hostnames(ips: list[str], per_host_timeout: float = 0.4) -> dict[str, str | None]:
        """DNS inverso concurrente con un tiempo de espera corto por host."""

        def resolve(ip: str) -> tuple[str, str | None]:
            previous = socket.getdefaulttimeout()
            socket.setdefaulttimeout(per_host_timeout)
            try:
                name = socket.gethostbyaddr(ip)[0]
                return ip, name
            except (OSError, socket.herror, socket.gaierror):
                return ip, None
            finally:
                socket.setdefaulttimeout(previous)

        workers = min(32, max(1, len(ips)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return dict(pool.map(resolve, ips))
