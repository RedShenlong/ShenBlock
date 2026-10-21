"""Pruebas de la capa visual (prompt y barra de progreso)."""

from __future__ import annotations

from datetime import datetime, timezone

from shenblock.models import Device
from shenblock.ui import ShenUI


def test_prompt_text_marks_blocked() -> None:
    ui = ShenUI()
    sin_bloqueo = ui.prompt_text("192.168.1.0/24", "wlan0", 7, 0)
    con_bloqueo = ui.prompt_text("192.168.1.0/24", "wlan0", 7, 3)
    assert "shenblock" in sin_bloqueo
    assert "wlan0" in sin_bloqueo and "192.168.1.0/24" in sin_bloqueo
    assert "⛔ 3" in con_bloqueo  # el contador de bloqueados aparece
    assert "⛔" not in sin_bloqueo


def test_scan_with_progress_runs_both_phases() -> None:
    ui = ShenUI()
    order: list[str] = []

    def raw() -> list[Device]:
        order.append("raw")
        return [Device("192.168.1.5", "00:00:00:00:00:05", datetime.now(timezone.utc))]

    def enrich(rows: list[Device]) -> list[Device]:
        order.append("enrich")
        return [row.with_enrichment(vendor="Cisco") for row in rows]

    devices = ui.scan_with_progress(raw, enrich, expected_seconds=0.05)
    assert order == ["raw", "enrich"]
    assert len(devices) == 1 and devices[0].vendor == "Cisco"


def test_scan_with_progress_propagates_errors() -> None:
    ui = ShenUI()

    def raw() -> list[Device]:
        raise OSError("fallo de red simulado")

    try:
        ui.scan_with_progress(raw, lambda rows: rows, expected_seconds=0.05)
    except OSError as error:
        assert "simulado" in str(error)
    else:  # pragma: no cover
        raise AssertionError("debería haberse propagado la excepción")
