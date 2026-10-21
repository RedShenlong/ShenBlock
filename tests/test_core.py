"""Pruebas que no requieren privilegios ni tarjeta de red."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from shenblock.models import Device, SessionPlan
from shenblock.oui import OuiResolver
from shenblock.ui import ShenUI


def make_device(ip: str, mac: str) -> Device:
    return Device(ip, mac, datetime.now(timezone.utc))


def test_oui_lookup_known_and_unknown() -> None:
    resolver = OuiResolver()
    assert resolver.lookup("b8:27:eb:12:34:56") == "Raspberry Pi"
    assert resolver.lookup("B8-27-EB-AA-BB-CC") == "Raspberry Pi"
    assert resolver.lookup("ff:ff:ff:00:00:00") is None


def test_device_enrichment_is_immutable_copy() -> None:
    device = make_device("192.168.1.5", "b8:27:eb:00:00:01")
    enriched = device.with_enrichment(vendor="Raspberry Pi", hostname="pi.local")
    assert device.vendor is None
    assert enriched.vendor == "Raspberry Pi"
    assert enriched.hostname == "pi.local"
    assert enriched.ip == device.ip


def test_parse_selection_ranges_and_all() -> None:
    devices = [make_device(f"192.168.1.{i}", f"00:00:00:00:00:0{i}") for i in range(1, 6)]
    assert ShenUI.parse_selection("all", devices) == devices
    assert ShenUI.parse_selection("1,3-4", devices) == [devices[0], devices[2], devices[3]]
    assert ShenUI.parse_selection("4-2", devices) == [devices[1], devices[2], devices[3]]


@pytest.mark.parametrize("raw", ["", "0", "9", "1-99", "abc"])
def test_parse_selection_rejects_invalid(raw: str) -> None:
    devices = [make_device("192.168.1.1", "00:00:00:00:00:01")]
    with pytest.raises(ValueError):
        ShenUI.parse_selection(raw, devices)


def test_session_plan_target_count() -> None:
    devices = [make_device("192.168.1.1", "00:00:00:00:00:01")]
    plan = SessionPlan(tuple(devices), 30, label="block")
    assert plan.target_count == 1
    assert plan.label == "block"


def test_export_json(tmp_path) -> None:
    from shenblock.cli import Shell

    class _FakeScanner:
        interface = "eth0"

        def source_ip(self):  # pragma: no cover - no se usa aquí
            return "192.168.1.2"

    shell = Shell.__new__(Shell)  # sin __init__ para no tocar la red
    shell.network = "192.168.1.0/24"
    shell.scanner = _FakeScanner()
    shell.devices = [
        make_device("192.168.1.5", "b8:27:eb:00:00:01").with_enrichment(vendor="Raspberry Pi")
    ]
    out = shell._export(str(tmp_path / "hosts.json"))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["network"] == "192.168.1.0/24"
    assert data["hosts"][0]["vendor"] == "Raspberry Pi"
