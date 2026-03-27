"""Centralna lista producentow dla filtrowania i prezentacji w GUI."""

VENDOR_OUI = {
    # Dodaj kolejne OUI w formacie "xx:xx:xx": "Nazwa producenta"
}

# Fallback: szukanie slow kluczowych po surowych bajtach pakietu ARP.
VENDOR_KEYWORDS = []

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
