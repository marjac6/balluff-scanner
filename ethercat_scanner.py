# ethercat_scanner.py
"""
EtherCAT scanner oparty na bibliotece pysoem (SOEM).
Wymaga: pip install pysoem
Wymaga w systemie: Npcap (tryb WinPcap compatible) lub WinPcap.
"""

import threading
import time
import struct
import pysoem
from debug_utils import get_logger, log_exception

log = get_logger(__name__)

# Prevent concurrent EtherCAT master operations (scan vs switch) on the same host.
_ECAT_MASTER_LOCK = threading.Lock()




# ─── Mapowanie adapter_name → NPF device path ─────────────────────────────────

def _get_pcap_name(adapter_name: str) -> str | None:
    if pysoem is None: return None
    
    # Opcjonalnie: zmniejsz poziom logowania dla mapowania, by nie śmiecić w konsoli
    # log.debug(f"Mapowanie adaptera: '{adapter_name}'")
    
    target_description = adapter_name
    try:
        from scanner import get_adapters
        for adp in get_adapters():
            if adp.get("name") == adapter_name:
                target_description = adp.get("description", adapter_name)
                break
    except Exception: pass

    try:
        interfaces = pysoem.find_adapters()
    except Exception: return None

    def _s(v):
        if hasattr(v, 'name'): return getattr(v, 'name').decode('utf-8', errors='replace') if isinstance(getattr(v, 'name'), bytes) else str(getattr(v, 'name'))
        if isinstance(v, bytes): return v.decode("utf-8", errors="replace")
        return str(v)
    
    def _d(v):
        if hasattr(v, 'desc'): return getattr(v, 'desc').decode('utf-8', errors='replace') if isinstance(getattr(v, 'desc'), bytes) else str(getattr(v, 'desc'))
        if isinstance(v, bytes): return v.decode("utf-8", errors="replace")
        return str(v)

    for iface in interfaces:
        pcap_name = _s(iface)
        pcap_desc = _d(iface)
        if target_description and target_description == pcap_desc: return pcap_name
        if adapter_name in pcap_name: return pcap_name
        if target_description and target_description in pcap_desc: return pcap_name
            
    return None


# ─── Pomocnicze dekodowanie ───────────────────────────────────────────────────

def _decode(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", errors="replace").strip("\x00").strip()
    return str(v).strip()

SDO_TIMEOUT_US = 300_000  # 300 ms per SDO read — prevents blocking on unresponsive slaves
SDO_INTER_WRITE_DELAY_S = 0.0
POST_SDO_BEFORE_INIT_DELAY_S = 0.06
POST_INIT_SETTLE_S = 2.5
# Balluff docs: 0xF502:02 = Protocol After Reboot.
# The protocol list is ordered as ATD, PNT, EIP, ECT, MBT.
# Note: 0=AUTO?, 1=?, 2=EIP, 3=?, 4=Modbus
# Profinet value to be confirmed with Balluff documentation
BALLUFF_PROTOCOL_AFTER_REBOOT_PROFINET = 3
BALLUFF_PROTOCOL_AFTER_REBOOT_EIP = 2
BALLUFF_PROTOCOL_AFTER_REBOOT_MODBUS = 4
# Official ETG Vendor ID for Balluff is 0x010000E8.
# Keep legacy 0x00000378 for compatibility with field captures and older tooling.
BALLUFF_VENDOR_IDS = {0x010000E8, 0x00000378}

def _sdo_string(slave, index: int, subindex: int = 0) -> str:
    """Bezpieczny odczyt SDO string z limitem czasu."""
    try:
        data = slave.sdo_read(index, subindex)
        return _decode(data)
    except Exception:
        return ""


def _sdo_write_flag(slave, index: int, subindex: int) -> tuple[bool, str]:
    """Write logical TRUE to a vendor object with payload size fallback."""
    last_err = ""
    # Prefer 8-bit BOOL first, then wider payloads for compatibility.
    payloads = (b"\x01", struct.pack("<H", 1), struct.pack("<I", 1))
    for payload in payloads:
        try:
            slave.sdo_write(index, subindex, payload)
            # Avoid immediate readback here: extra mailbox uploads can alter timing
            # around vendor apply/restart handling on some devices.
            return True, ""
        except Exception as e:
            last_err = str(e)
    return False, last_err


def _sdo_write_u16_one(slave, index: int, subindex: int) -> tuple[bool, str]:
    """Strict write used to mirror reference sequence payload as 16-bit value = 1."""
    try:
        slave.sdo_write(index, subindex, struct.pack("<H", 1))
        return True, ""
    except Exception as e:
        return False, str(e)


def _sdo_write_u8(slave, index: int, subindex: int, value: int) -> tuple[bool, str]:
    """Write an 8-bit value for enum/bool-style CoE objects."""
    try:
        slave.sdo_write(index, subindex, struct.pack("<B", int(value) & 0xFF))
        return True, ""
    except Exception as e:
        return False, str(e)


def _sdo_read_probe(slave, index: int, subindex: int) -> None:
    """Best-effort read used to prime mailbox/SDO path before writes."""
    try:
        slave.sdo_read(index, subindex)
    except Exception:
        pass


def _sdo_read_u32(slave, index: int, subindex: int) -> int | None:
    """Best-effort SDO numeric read (little-endian)."""
    try:
        data = slave.sdo_read(index, subindex)
        if not data:
            return None
        return int.from_bytes(data[: min(4, len(data))], byteorder="little", signed=False)
    except Exception:
        return None


def switch_balluff_xg_protocol(
    adapter_name: str,
    slave_index: int,
    target_protocol: str,  # "profinet" | "eip" | "modbus"
    expected_vendor_id: int | None = None,
    expected_product_code: int | None = None,
    expected_serial: int | None = None,
) -> tuple[bool, str]:
    """Switch Balluff BNI XG EtherCAT slave to target protocol (Profinet, EtherNet/IP, or Modbus TCP).

    The sequence uses mailbox CoE downloads to 0xF502:02 (Protocol After Reboot).
    """
    protocol_map = {
        "profinet": (BALLUFF_PROTOCOL_AFTER_REBOOT_PROFINET, "Profinet"),
        "eip": (BALLUFF_PROTOCOL_AFTER_REBOOT_EIP, "EtherNet/IP"),
        "modbus": (BALLUFF_PROTOCOL_AFTER_REBOOT_MODBUS, "Modbus TCP"),
    }
    
    if target_protocol.lower() not in protocol_map:
        return False, f"Nieznany protokół: {target_protocol}"
    
    protocol_value, protocol_name = protocol_map[target_protocol.lower()]
    
    if pysoem is None:
        return False, "pysoem nie jest dostępny"

    pcap_name = _get_pcap_name(adapter_name)
    if not pcap_name:
        return False, f"Nie znaleziono adaptera EtherCAT dla: {adapter_name}"

    # Wait briefly for any ongoing scan cycle to release the EtherCAT master path.
    if not _ECAT_MASTER_LOCK.acquire(timeout=5.0):
        return False, "EtherCAT jest zajęty (trwa skanowanie). Spróbuj ponownie za chwilę."

    master = pysoem.Master()
    try:
        master.open(pcap_name)
        master.sdo_read_timeout = SDO_TIMEOUT_US
        master.sdo_write_timeout = SDO_TIMEOUT_US

        slave_count = master.config_init()
        if slave_count <= 0:
            return False, "Brak slave'ów EtherCAT na wybranym adapterze"

        if slave_index < 0 or slave_index >= slave_count:
            return False, f"Nieprawidłowy indeks slave: {slave_index} (max={slave_count - 1})"

        slave = master.slaves[slave_index]

        vid = int(getattr(slave, "man", 0) or 0)
        pid = int(getattr(slave, "id", 0) or 0)
        serial = int(getattr(slave, "serial", 0) or 0)

        if expected_vendor_id is not None and vid != int(expected_vendor_id):
            return False, (
                "Niezgodny target slave (VendorID): "
                f"oczekiwano 0x{int(expected_vendor_id):08X}, otrzymano 0x{vid:08X}"
            )
        if expected_product_code is not None and pid != int(expected_product_code):
            return False, (
                "Niezgodny target slave (ProductCode): "
                f"oczekiwano 0x{int(expected_product_code):08X}, otrzymano 0x{pid:08X}"
            )
        if expected_serial is not None and serial != int(expected_serial):
            return False, (
                "Niezgodny target slave (Serial): "
                f"oczekiwano 0x{int(expected_serial):08X}, otrzymano 0x{serial:08X}"
            )

        if vid not in BALLUFF_VENDOR_IDS:
            return False, f"Urządzenie nie jest Balluff (VendorID=0x{vid:08X})"

        # Keep pre-switch chatter minimal; prefer SII name here and avoid
        # extra mailbox reads right before the 3 critical downloads.
        sii_name = _decode(getattr(slave, "name", ""))
        display_name = (sii_name or "").strip()
        # Accept generic EtherCAT names (e.g. EtherCATFieldbusModulesBNI).
        # Reject only when a non-generic name clearly does not look like BNI.
        if display_name and not _is_generic_ecat_name(display_name):
            if "BNI" not in display_name.upper():
                return False, f"Urządzenie nie pasuje do BNI XG* ({display_name})"

        sequence = (
            (0xF502, 0x02, protocol_value),
            (0xF503, 0x01, 1),
            (0xF503, 0x02, 1),
        )
        last_err = ""
        for attempt in (0, 1):
            if attempt == 1:
                # Fallback only: force PRE-OP if first pass failed.
                try:
                    slave.state = pysoem.PREOP_STATE
                    if hasattr(slave, "write_state"):
                        slave.write_state()
                    else:
                        master.write_state()
                    master.state_check(pysoem.PREOP_STATE, 300_000)
                except Exception:
                    pass

            failed = False
            for i, (idx, sub, value) in enumerate(sequence):
                ok, err = _sdo_write_u8(slave, idx, sub, value)
                if not ok:
                    last_err = f"Błąd zapisu SDO 0x{idx:04X}:{sub:02d} ({err})"
                    failed = True
                    break
                if i < len(sequence) - 1 and SDO_INTER_WRITE_DELAY_S > 0:
                    time.sleep(SDO_INTER_WRITE_DELAY_S)

            if not failed:
                break
        else:
            return False, last_err or "Błąd zapisu sekwencji SDO"

        # Keep a short gap before final settle window.
        time.sleep(POST_SDO_BEFORE_INIT_DELAY_S)

        # Keep session alive without extra mailbox chatter/AL control writes to
        # match the reference trace after final Scs 3.
        time.sleep(POST_INIT_SETTLE_S)

        if display_name:
            return True, f"✓ Wysłano sekwencję do {protocol_name} ({display_name}). Urządzenie uruchomi się ponownie w nowym protokole."
        return True, f"✓ Wysłano sekwencję do {protocol_name}. Urządzenie uruchomi się ponownie w nowym protokole."
    except Exception as e:
        log_exception(log, "Błąd przełączenia protokołu EtherCAT", e)
        return False, f"Błąd: {e}"
    finally:
        try:
            master.close()
        except Exception:
            pass
        _ECAT_MASTER_LOCK.release()


def switch_balluff_xg_to_eip(
    adapter_name: str,
    slave_index: int,
    expected_vendor_id: int | None = None,
    expected_product_code: int | None = None,
    expected_serial: int | None = None,
) -> tuple[bool, str]:
    """Legacy wrapper: Switch Balluff BNI XG EtherCAT slave to Ethernet/IP mode.
    
    Calls switch_balluff_xg_protocol() with target_protocol="eip" for backward compatibility.
    """
    return switch_balluff_xg_protocol(
        adapter_name=adapter_name,
        slave_index=slave_index,
        target_protocol="eip",
        expected_vendor_id=expected_vendor_id,
        expected_product_code=expected_product_code,
        expected_serial=expected_serial,
    )


def switch_balluff_xg_to_profinet(
    adapter_name: str,
    slave_index: int,
    expected_vendor_id: int | None = None,
    expected_product_code: int | None = None,
    expected_serial: int | None = None,
) -> tuple[bool, str]:
    """Switch Balluff BNI XG EtherCAT slave to PROFINET DCP mode."""
    return switch_balluff_xg_protocol(
        adapter_name=adapter_name,
        slave_index=slave_index,
        target_protocol="profinet",
        expected_vendor_id=expected_vendor_id,
        expected_product_code=expected_product_code,
        expected_serial=expected_serial,
    )


def switch_balluff_xg_to_modbus(
    adapter_name: str,
    slave_index: int,
    expected_vendor_id: int | None = None,
    expected_product_code: int | None = None,
    expected_serial: int | None = None,
) -> tuple[bool, str]:
    """Switch Balluff BNI XG EtherCAT slave to Modbus TCP mode."""
    return switch_balluff_xg_protocol(
        adapter_name=adapter_name,
        slave_index=slave_index,
        target_protocol="modbus",
        expected_vendor_id=expected_vendor_id,
        expected_product_code=expected_product_code,
        expected_serial=expected_serial,
    )



def _sdo_string_retry(slave, index: int, subindex: int = 0, attempts: int = 4, sleep_s: float = 0.03) -> str:
    """Ponawia odczyt SDO, bo mailbox bywa chwilowo niedostepny zaraz po przejsciu do PRE-OP."""
    value = ""
    for n in range(max(1, attempts)):
        value = _sdo_string(slave, index, subindex)
        if value:
            return value
        if n < attempts - 1:
            time.sleep(sleep_s)
    return value


def _is_generic_ecat_name(name: str) -> bool:
    """Wykrywa ogolne nazwy urzadzenia, ktore nie wskazuja konkretnego modelu."""
    if not name:
        return True
    lowered = name.lower().replace(" ", "")
    generic_tokens = (
        "ethercatfieldbusmodules",
        "ethercat",
        "fieldbusmodule",
    )
    return any(token in lowered for token in generic_tokens)


def _pick_product_name(device_name: str, sii_name: str, slave_index: int) -> str:
    """Preferuje konkretna nazwe modelu (SII) zamiast ogolnego opisu z 0x1008."""
    if sii_name and not _is_generic_ecat_name(sii_name):
        return sii_name
    if device_name and not _is_generic_ecat_name(device_name):
        return device_name
    if sii_name:
        return sii_name
    if device_name:
        return device_name
    return f"EtherCAT Slave #{slave_index}"


def _pick_product_name_with_source(device_name: str, sii_name: str, slave_index: int) -> tuple[str, str]:
    """Zwraca nazwe produktu i zrodlo tej nazwy (SII/SDO/FALLBACK)."""
    if sii_name and not _is_generic_ecat_name(sii_name):
        return sii_name, "SII"
    if device_name and not _is_generic_ecat_name(device_name):
        return device_name, "SDO_0x1008"
    if sii_name:
        return sii_name, "SII_GENERIC"
    if device_name:
        return device_name, "SDO_0x1008_GENERIC"
    return f"EtherCAT Slave #{slave_index}", "FALLBACK"

# ─── Główna logika skanowania ─────────────────────────────────────────────────

def _active_scan(adapter_name: str, callback, stop_event):
    if pysoem is None or stop_event.is_set(): return

    log.info(f"--- Skanowanie EtherCAT: {adapter_name} ---")

    pcap_name = _get_pcap_name(adapter_name)
    if not pcap_name: return

    # Serialize with switch operation to avoid mixed mailbox/state traffic.
    with _ECAT_MASTER_LOCK:
        master = pysoem.Master()
        
        # Zmniejszamy timeouty, aby przycisk Stop reagował szybciej
        try:
            master.open(pcap_name)
            master.sdo_read_timeout = SDO_TIMEOUT_US
            master.sdo_write_timeout = SDO_TIMEOUT_US
            if stop_event.is_set(): 
                master.close()
                return

            # 1. Wykrycie slave'ów
            slave_count = master.config_init()
            log.info(f"config_init: {slave_count} slave(s)")
            
            if slave_count <= 0:
                master.close()
                return

            # 2. Przejście do PRE-OP
            # Timeout skalowany liniowo: 300 ms * liczba slave'ów (minimum 300 ms)
            preop_timeout_us = 300_000 * max(1, slave_count)
            for slave in master.slaves:
                slave.state = pysoem.PREOP_STATE
            master.write_state()
            master.state_check(pysoem.PREOP_STATE, preop_timeout_us)
            log.debug(f"state_check PRE-OP timeout={preop_timeout_us//1000} ms dla {slave_count} slave(s)")
            
            if stop_event.is_set(): 
                master.close()
                return

            # 3. Odczyt danych
            for i, slave in enumerate(master.slaves):
                if stop_event.is_set(): break

                # Identity
                vid = getattr(slave, "man", 0) or 0
                pid = getattr(slave, "id",  0) or 0
                rev = getattr(slave, "rev", 0) or 0
                
                # SDO (tylko jesli slave w PRE-OP)
                device_name = ""
                sw_version = ""
                
                # Sprawdź stan przed próbą odczytu
                if slave.state == pysoem.PREOP_STATE:
                    device_name = _sdo_string_retry(slave, 0x1008)
                    if stop_event.is_set(): break
                    sw_version  = _sdo_string_retry(slave, 0x100A)
                
                # Fallback
                sii_name = _decode(getattr(slave, "name", ""))
                product_name, product_name_source = _pick_product_name_with_source(device_name, sii_name, i)

                info = {
                    "mac":          "N/A",
                    "ip":           "",
                    "product_name": product_name,
                    "sw_version":   sw_version or f"Rev: {rev:#x}",
                    "device_name_sdo": device_name,
                    "sii_name":     sii_name,
                    "product_name_source": product_name_source,
                    "slave_count":  slave_count,
                    "slave_index":  i,
                    "name":         product_name,
                    "protocol":     "EtherCAT",
                    "adapter":      adapter_name,
                    "vendor_id":    f"0x{vid:08X}",
                    "product_code": f"0x{pid:08X}",
                    "revision":     f"0x{rev:08X}",
                    "serial":       f"0x{getattr(slave, 'serial', 0):08X}",
                    "vendor_id_dec": vid,
                    "product_code_dec": pid,
                    "revision_dec": rev,
                    "serial_dec": getattr(slave, 'serial', 0),
                    "_update":      False,
                }

                if not stop_event.is_set():
                    callback(info)

        except Exception as e:
            # Nie loguj błędów przerwania (np. gdy close() w trakcie read())
            log_exception(log, "Wyjątek EtherCAT", e, ["reset by peer", "socket"])
        finally:
            try: master.close()
            except: pass


# ─── Public API ───────────────────────────────────────────────────────────────

def start_ecat_scan(adapter_name: str, callback, stop_event):
    """
    Skanuje pojedynczy adapter.
    """
    # Pierwsze skanowanie
    _active_scan(adapter_name, callback, stop_event)

    # Pętla odświeżania (co 10 sekund)
    while not stop_event.is_set():
        # Reagujemy na stop co 0.1s, nie musimy czekać pełne 10s
        for _ in range(100):
            if stop_event.is_set(): return
            time.sleep(0.1)
        
        # Ponów skanowanie
        _active_scan(adapter_name, callback, stop_event)


def start_ecat_scan_all(callback, stop_event):
    """Skanuje wszystkie dostępne adaptery jednocześnie."""
    if pysoem is None: return []

    from scanner import get_adapters
    adapters = get_adapters()
    threads = []
    for adapter in adapters:
        name = adapter.get("name", "")
        if not name: continue
        
        t = threading.Thread(
            target=start_ecat_scan,
            args=(name, callback, stop_event),
            daemon=True,
        )
        t.start()
        threads.append(t)
    return threads