"""Pruebas de identificación de fabricante y formateo visual."""

from __future__ import annotations

from datetime import datetime, timezone

from shenblock.models import Device
from shenblock.oui import OuiResolver
from shenblock.ui import ShenUI


def test_embedded_oui_still_works() -> None:
    resolver = OuiResolver(use_scapy=False)
    assert resolver.lookup("b8:27:eb:00:00:01") == "Raspberry Pi"
    assert resolver.lookup("ff:ff:ff:00:00:00") is None


def test_scapy_fallback_resolves_more_vendors() -> None:
    resolver = OuiResolver()  # con la BD de Scapy
    # Un prefijo que NO está en la tabla embebida pero sí en Scapy.
    vendor = resolver.lookup("00:0c:29:12:34:56")  # VMware
    assert vendor is not None and vendor != "00:0c:29:12:34:56"


def test_human_rate_units() -> None:
    assert ShenUI.human_rate(512).endswith("B/s")
    assert ShenUI.human_rate(2048) == "2.0 KB/s"
    assert ShenUI.human_rate(5 * 1024 * 1024) == "5.0 MB/s"


def test_rate_bar_scales_with_peak() -> None:
    empty = ShenUI.rate_bar(0, peak=100, width=10)
    full = ShenUI.rate_bar(100, peak=100, width=10)
    assert "█" not in empty
    assert "█" in full


def test_random_mac_detection() -> None:
    # Bit localmente administrado activo => aleatoria (iPhone/Android).
    assert ShenUI.is_random_mac("a6:83:e7:11:22:33") is True
    assert ShenUI.is_random_mac("aa:bb:cc:dd:ee:ff") is True
    # MAC real de fabricante (Raspberry Pi) => no aleatoria.
    assert ShenUI.is_random_mac("b8:27:eb:00:00:01") is False


def test_vendor_cell_labels_private_mac() -> None:
    ui = ShenUI()
    now = datetime.now(timezone.utc)
    known = Device("192.168.1.5", "b8:27:eb:00:00:01", now, vendor="Raspberry Pi")
    private = Device("192.168.1.6", "a6:83:e7:11:22:33", now)
    unknown = Device("192.168.1.7", "b8:27:eb:ff:ff:ff", now)
    assert ui.vendor_cell(known) == "Raspberry Pi"
    assert "privada" in ui.vendor_cell(private)
    assert ui.vendor_cell(unknown) == "[muted]—[/]"


def test_tables_render_without_error() -> None:
    ui = ShenUI()
    devices = [
        Device("192.168.1.5", "b8:27:eb:00:00:01", datetime.now(timezone.utc), vendor="Raspberry Pi"),
        Device("192.168.1.1", "aa:bb:cc:dd:ee:ff", datetime.now(timezone.utc)),
    ]
    blocked = {"192.168.1.5"}
    rates = {"192.168.1.5": 1500.0, "192.168.1.1": 0.0}
    # No deben lanzar excepción al construir/renderizar.
    ui.devices_table(devices, blocked=blocked, gateway_ip="192.168.1.1")
    table = ui.bandwidth_dashboard(devices, rates, blocked, gateway_ip="192.168.1.1")
    assert table.row_count == 2
