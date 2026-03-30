"""Centralna lista producentow dla filtrowania i prezentacji w GUI."""

VENDOR_OUI = {
    # Dodaj kolejne OUI w formacie "xx:xx:xx": "Nazwa producenta"
}

# Fallback: szukanie slow kluczowych po surowych bajtach pakietu ARP.
VENDOR_KEYWORDS = []

# ── IEEE OUI lookup via scapy manuf database ─────────────────────────────────

_SCAPY_OUI_CACHE: dict[str, str] | None = None


def _load_scapy_oui() -> dict[str, str]:
    """Parse scapy's bundled IEEE OUI database into a dict {oui: long_name}."""
    global _SCAPY_OUI_CACHE
    if _SCAPY_OUI_CACHE is not None:
        return _SCAPY_OUI_CACHE
    result: dict[str, str] = {}
    try:
        from scapy.libs import manuf as _manuf
        for line in _manuf.DATA.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                oui = parts[0].strip().lower()
                long_name = parts[2].strip()
                if oui and long_name:
                    result[oui] = long_name
            elif len(parts) == 2:
                oui = parts[0].strip().lower()
                short_name = parts[1].strip()
                if oui and short_name:
                    result[oui] = short_name
    except Exception:
        pass
    _SCAPY_OUI_CACHE = result
    return result


def _oui_from_mac(mac: str) -> str:
    """Return the OUI (first 3 octets) of a MAC address, lower-case colon-separated."""
    parts = (mac or "").lower().replace("-", ":").split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def _looks_like_oui(value: str) -> bool:
    """Return True if *value* is a raw OUI prefix, e.g. '00:19:31'."""
    import re
    return bool(re.fullmatch(r"[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}", (value or "").strip()))


def lookup_vendor_from_mac(mac: str) -> str:
    """Return manufacturer name for a MAC address using the IEEE OUI database.

    Checks ``VENDOR_OUI`` first (manual overrides), then falls back to the
    scapy bundled IEEE OUI database.  Returns an empty string if not found.
    """
    oui = _oui_from_mac(mac)
    if not oui:
        return ""
    # Manual override takes priority.
    if oui in VENDOR_OUI:
        return VENDOR_OUI[oui]
    return _load_scapy_oui().get(oui, "")

PROTOCOL_VENDOR_IDS = {
    "ethercat": {},
    "profinet": {},
    "ethernet/ip": {
        # Uzupełniane lokalnie np. na podstawie ODVA VID.
    },
}


def _normalize_vendor_id(vendor_id) -> str:
    if vendor_id is None:
        return ""
    if isinstance(vendor_id, int):
        return f"0x{vendor_id:X}"

    text = str(vendor_id).strip()
    if not text:
        return ""

    if text.lower().startswith("0x"):
        try:
            number = int(text, 16)
            return f"0x{number:X}"
        except ValueError:
            return text.upper()

    try:
        number = int(text, 16)
        return f"0x{number:X}"
    except ValueError:
        return text.upper()


def lookup_vendor_name(vendor_id, protocol: str | None = None) -> str:
    normalized = _normalize_vendor_id(vendor_id)
    if not normalized:
        return ""

    # Sprawdz kilka typowych wariantow zapisu.
    variants = {
        normalized,
        normalized.upper(),
    }
    if normalized.lower().startswith("0x"):
        try:
            n = int(normalized, 16)
            variants.add(f"0x{n:04X}")
            variants.add(f"0x{n:08X}")
        except ValueError:
            pass

    registries = []
    if protocol:
        registries.append(PROTOCOL_VENDOR_IDS.get(protocol.lower(), {}))
    else:
        registries.extend(PROTOCOL_VENDOR_IDS.values())

    for registry in registries:
        for key in variants:
            if key in registry:
                return registry[key]
    return ""
