"""Pruebas del monitor de ancho de banda SIN capturar tráfico real.

Se alimenta ``_on_packet`` con paquetes construidos en memoria (no se abre
ningún sniffer), y se fuerza el cálculo de tasas con ``_compute_rates``.
"""

from __future__ import annotations

from scapy.all import IP, Raw

from shenblock.monitor import BandwidthMonitor


def test_accounting_up_and_down() -> None:
    monitor = BandwidthMonitor("eth0")
    # 192.168.1.5 sube un paquete hacia 8.8.8.8 y recibe otro de vuelta.
    monitor._on_packet(IP(src="192.168.1.5", dst="8.8.8.8") / Raw(b"x" * 100))
    monitor._on_packet(IP(src="8.8.8.8", dst="192.168.1.5") / Raw(b"y" * 200))
    monitor._compute_rates()

    rates = monitor.rates()
    assert "192.168.1.5" in rates
    up, down = rates["192.168.1.5"]
    assert up > 0 and down > 0
    assert monitor.total_bps("192.168.1.5") == up + down
    assert monitor.rates_total()["192.168.1.5"] > 0


def test_idle_rate_decays_to_zero() -> None:
    monitor = BandwidthMonitor("eth0")
    monitor._on_packet(IP(src="192.168.1.9", dst="8.8.8.8") / Raw(b"z" * 50))
    monitor._compute_rates()
    assert monitor.total_bps("192.168.1.9") > 0
    # Sin tráfico nuevo, el delta es 0 y la tasa cae a 0.
    monitor._compute_rates()
    assert monitor.total_bps("192.168.1.9") == 0.0


def test_non_ip_packet_ignored() -> None:
    monitor = BandwidthMonitor("eth0")
    monitor._on_packet(Raw(b"no-ip"))
    monitor._compute_rates()
    assert monitor.rates() == {}
