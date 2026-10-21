"""Resolución offline del fabricante a partir del prefijo OUI de un MAC.

No requiere red ni dependencias externas. Trae un diccionario pequeño con
fabricantes habituales y, de forma opcional, puede cargar un fichero estilo
``manuf`` (el que distribuye Wireshark/Scapy) si el usuario lo indica, para
obtener cobertura completa sin tocar el resto del código.
"""

from __future__ import annotations

from pathlib import Path


def _load_scapy_manufdb():
    """Devuelve la base de fabricantes de Scapy, o ``None`` si no está disponible."""
    try:
        from scapy.all import conf  # type: ignore[import-untyped]

        manufdb = getattr(conf, "manufdb", None)
        return manufdb if hasattr(manufdb, "_get_manuf") else None
    except Exception:  # noqa: BLE001 - Scapy puede no estar o fallar al cargar
        return None

# Prefijos OUI (primeros 24 bits del MAC) de fabricantes frecuentes en redes
# domésticas y de laboratorio. La clave son los 3 primeros octetos en minúscula
# sin separadores. No pretende ser exhaustivo: es un punto de partida útil.
_COMMON_OUI: dict[str, str] = {
    "fcfbfb": "Cisco",
    "001a2b": "Cisco",
    "0050ba": "D-Link",
    "1c7ee5": "D-Link",
    "0025f2": "Asus",
    "ac220b": "Asus",
    "b827eb": "Raspberry Pi",
    "dca632": "Raspberry Pi",
    "e45f01": "Raspberry Pi",
    "001e8c": "Asus",
    "f0272d": "Intel",
    "a4c3f0": "Intel",
    "3c5ab4": "Google",
    "f4f5e8": "Google",
    "d8eb97": "TP-Link",
    "50c7bf": "TP-Link",
    "a842a1": "TP-Link",
    "e8de27": "TP-Link",
    "001132": "Synology",
    "0011d8": "Asus",
    "c46e1f": "TP-Link",
    "f09fc2": "Ubiquiti",
    "fcecda": "Ubiquiti",
    "245a4c": "Ubiquiti",
    "b4fbe4": "Ubiquiti",
    "acde48": "Private",
    "3c0754": "Apple",
    "a85c2c": "Apple",
    "f0d1a9": "Apple",
    "acbc32": "Apple",
    "d0817a": "Apple",
    "f45c89": "Apple",
    "001124": "Samsung",
    "5001bb": "Samsung",
    "8c7712": "Samsung",
    "e8508b": "Xiaomi",
    "fc64ba": "Xiaomi",
    "286c07": "Xiaomi",
    "7cf854": "Huawei",
    "00259e": "Huawei",
    "48ad08": "Huawei",
    "001c42": "Parallels",
    "000c29": "VMware",
    "005056": "VMware",
    "0003ff": "Microsoft",
    "0017fa": "Microsoft",
    "525400": "QEMU/KVM",
    "080027": "VirtualBox",
    "0a0027": "VirtualBox",
}


class OuiResolver:
    """Traduce un MAC a su fabricante.

    Resuelve en tres pasos: primero la tabla embebida, luego la base de datos de
    fabricantes que trae Scapy (miles de prefijos, sin red) y, por último, un
    fichero ``manuf`` opcional cargado por el usuario.
    """

    def __init__(self, table: dict[str, str] | None = None, use_scapy: bool = True) -> None:
        self._table: dict[str, str] = dict(_COMMON_OUI)
        if table:
            self._table.update(table)
        self._scapy = _load_scapy_manufdb() if use_scapy else None

    @staticmethod
    def _prefix(mac: str) -> str:
        """Normaliza un MAC a sus 3 primeros octetos (6 hex, minúscula)."""
        clean = mac.lower().replace(":", "").replace("-", "").replace(".", "")
        return clean[:6]

    def lookup(self, mac: str) -> str | None:
        """Devuelve el fabricante del MAC o ``None`` si no se reconoce."""
        vendor = self._table.get(self._prefix(mac))
        if vendor:
            return vendor
        if self._scapy is not None:
            try:
                found = self._scapy._get_manuf(mac)
            except Exception:  # noqa: BLE001 - la BD de Scapy puede lanzar o faltar
                return None
            # Cuando no conoce el prefijo, Scapy devuelve el propio MAC.
            if found and found.lower() != mac.lower():
                return found
        return None

    @classmethod
    def from_manuf_file(cls, path: str | Path) -> "OuiResolver":
        """Construye un resolver ampliado leyendo un fichero estilo ``manuf``.

        Cada línea útil tiene la forma ``AA:BB:CC\\tVendor`` (se ignoran
        comentarios ``#`` y máscaras largas). Si el fichero no existe, se
        devuelve el resolver con la tabla embebida por defecto.
        """
        table: dict[str, str] = {}
        file_path = Path(path)
        if not file_path.is_file():
            return cls()
        for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            raw_prefix = parts[0].split("/")[0]
            prefix = raw_prefix.lower().replace(":", "").replace("-", "").replace(".", "")
            if len(prefix) >= 6:
                table[prefix[:6]] = parts[1].strip()
        return cls(table)
