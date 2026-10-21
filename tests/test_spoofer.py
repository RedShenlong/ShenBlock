"""Pruebas del spoofer y la acción SIN enviar paquetes reales a la red.

Se parchea ``scapy.send`` para capturar los paquetes en memoria, de modo que se
verifica la construcción y la lógica de restauración sin tocar la tarjeta.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from shenblock import spoofer as spoofer_module
from shenblock.models import Device
from shenblock.spoofer import ARPSpoofer, Target


@pytest.fixture
def captured(monkeypatch):
    sent: list = []
    monkeypatch.setattr(spoofer_module, "sendp", lambda packet, **kwargs: sent.append(packet))
    return sent


def make_spoofer() -> ARPSpoofer:
    return ARPSpoofer("eth0", "192.168.1.1", "aa:bb:cc:dd:ee:ff", interval=0.1)


def test_add_and_targets_are_sorted() -> None:
    spoofer = make_spoofer()
    spoofer.add("192.168.1.20", "00:00:00:00:00:14")
    spoofer.add("192.168.1.5", "00:00:00:00:00:05")
    ips = [target.ip for target in spoofer.targets()]
    assert ips == ["192.168.1.20", "192.168.1.5"] or ips == sorted(ips)
    assert Target("192.168.1.5", "00:00:00:00:00:05") in spoofer.targets()


def test_send_spoofed_builds_two_packets(captured) -> None:
    spoofer = make_spoofer()
    spoofer._send_spoofed(Target("192.168.1.5", "00:00:00:00:00:05"))
    assert len(captured) == 2
    to_gateway, to_victim = captured
    assert to_gateway.psrc == "192.168.1.5" and to_gateway.pdst == "192.168.1.1"
    assert to_victim.psrc == "192.168.1.1" and to_victim.pdst == "192.168.1.5"


def test_remove_restores(captured) -> None:
    spoofer = make_spoofer()
    spoofer.add("192.168.1.5", "00:00:00:00:00:05")
    captured.clear()
    spoofer.remove("192.168.1.5", restore=True)
    # El restore emite 2 paquetes correctores.
    assert len(captured) == 2
    assert all(packet.hwdst == spoofer_module.BROADCAST for packet in captured)
    assert spoofer.targets() == []


def test_invalid_interval() -> None:
    with pytest.raises(ValueError):
        ARPSpoofer("eth0", "192.168.1.1", "aa:bb:cc:dd:ee:ff", interval=0)


def test_action_block_free(captured, monkeypatch) -> None:
    from shenblock.action import LaboratoryAction

    # Evitar tocar /proc en el test.
    monkeypatch.setattr("shenblock.system.IpForwarding.read", lambda self: True)
    monkeypatch.setattr("shenblock.system.IpForwarding.set", lambda self, enabled: True)

    action = LaboratoryAction("eth0", "192.168.1.1", "aa:bb:cc:dd:ee:ff", interval=0.1)
    device = Device("192.168.1.5", "00:00:00:00:00:05", datetime.now(timezone.utc))
    assert action.block([device]) == 1
    assert action.running is True
    assert "objetivo" in (action.refresh() or "")
    remaining = action.free([device])
    assert remaining == 0
    assert action.running is False
