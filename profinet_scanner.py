# profinet_scanner.py
import threading
import struct
import time
from scapy.all import sendp, sniff, Ether, Raw, get_if_hwaddr
from debug_utils import get_logger, log_exception

logger = get_logger(__name__)

PROFINET_MULTICAST = "01:0e:cf:00:00:00"
PROFINET_ETHERTYPE = 0x8892

# DCP SET XID counter (incremented per request for response matching)
_dcp_xid = 0x10000001


def _normalize_mac(mac: str) -> str:
    return (mac or "").strip().lower().replace("-", ":")


def _adapter_src_mac(adapter_name: str) -> str:
    """Resolve adapter source MAC for raw L2 send on Windows/Npcap."""
    needle = (adapter_name or "").strip().lower()

    try:
        from scanner import get_adapters
        for a in get_adapters():
            name = (a.get("name") or "").strip().lower()
            desc = (a.get("description") or "").strip().lower()
            mac = _normalize_mac(a.get("mac") or "")
            if not mac or mac == "00:00:00:00:00:00":
                continue
            if needle == name or needle == desc or (name and name in needle) or (desc and desc in needle):
                return mac
    except Exception:
        pass

    try:
        mac = _normalize_mac(get_if_hwaddr(adapter_name))
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass

    return ""


def _next_xid():
    global _dcp_xid
    _dcp_xid = (_dcp_xid + 1) & 0xFFFFFFFF
    return _dcp_xid


def _build_dcp_set_frame(xid: int, blocks_payload: bytes) -> bytes:
    """Build a DCP SET request header + blocks.

    DCP Set/Get uses Frame-ID 0xFEFD in practice (matches ProfinetSet/Wireshark decode).
    """
    frame_id     = 0xFEFD          # DCP Set/Get request/response
    service_id   = 0x04            # Set
    service_type = 0x00            # Request
    response_delay = 0x0000        # unicast – no delay
    data_length  = len(blocks_payload)

    header = struct.pack(">HBBHHHH",
        frame_id,
        service_id, service_type,
        xid & 0xFFFF, (xid >> 16) & 0xFFFF,
        response_delay,
        data_length,
    )
    return header + blocks_payload


def _dcp_block(opt: int, subopt: int, value: bytes, qualifier: int = 0x0001) -> bytes:
    """Build one DCP block with BlockQualifier (2 bytes) prepended to value."""
    block_value = struct.pack(">H", qualifier) + value
    length = len(block_value)
    block = struct.pack(">BBH", opt, subopt, length) + block_value
    # Pad to even length
    if len(block) % 2:
        block += b'\x00'
    return block


def _dcp_set_send_and_listen(
    adapter_name: str,
    target_mac: str,
    pkt,
    timeout: float = 2.0,
) -> tuple[bool, str]:
    """Send a DCP SET unicast frame and wait for a response from the device.

    DCP SET responses are OPTIONAL per IEC 61158-6-10 — many devices apply
    the setting silently without sending any confirmation frame.  Therefore:
      - Confirmed positive response  → (True,  "OK — potwierdzone przez urządzenie")
      - Confirmed negative response  → (False, "Urządzenie odrzuciło …")
      - No response within timeout   → (True,  "Wysłano — brak odpowiedzi …") [normal]
    """
    target_mac_norm = target_mac.lower().replace("-", ":")
    result: dict = {"ok": None, "msg": ""}
    stop = threading.Event()

    def handler(pkt_r):
        if stop.is_set():
            return
        if not pkt_r.haslayer(Ether):
            return
        src = (pkt_r[Ether].src or "").lower().replace("-", ":")
        if src != target_mac_norm:
            return
        _, payload = extract_profinet_payload(pkt_r)
        if payload is None or len(payload) < 12:
            return
        try:
            p_service_id = payload[2]
            p_srv_type   = payload[3]
            # Accept any DCP SET response (service=0x04, type=0x01) from this MAC.
            # XID is intentionally NOT checked — some devices respond with a different XID.
            if p_service_id != 0x04 or p_srv_type != 0x01:
                return
            # Scan blocks for opt=0x05 (Control) suboption with error code
            data_length = struct.unpack_from(">H", payload, 10)[0]
            offset = 12
            end    = min(offset + data_length, len(payload))
            error_code = 0x00
            while offset + 4 <= end:
                b_opt = payload[offset]
                b_len = struct.unpack_from(">H", payload, offset + 2)[0]
                offset += 4
                block_data = payload[offset:offset + b_len]
                offset += b_len + (b_len % 2)
                if b_opt == 0x05 and len(block_data) >= 3:
                    error_code = block_data[2]
            if error_code == 0x00:
                result["ok"]  = True
                result["msg"] = "OK — potwierdzone przez urządzenie"
            else:
                result["ok"]  = False
                result["msg"] = f"Urządzenie odrzuciło żądanie (kod błędu DCP: 0x{error_code:02X})"
            stop.set()
        except Exception as e:
            log_exception(logger, "DCP SET response parse error", e)

    def run_sniffer():
        try:
            sniff(
                iface=adapter_name,
                prn=handler,
                stop_filter=lambda _p: stop.is_set(),
                timeout=timeout,
                # Do not use BPF ether proto filter here: many PN devices answer
                # inside 802.1Q VLAN frames (ethertype 0x8100), which would be dropped.
                store=False,
            )
        except Exception as e:
            log_exception(logger, "DCP SET sniffer error", e)
        finally:
            stop.set()

    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()

    # Give the pcap handle time to open before sending.
    time.sleep(0.15)
    sendp(pkt, iface=adapter_name, verbose=False)

    sniffer_thread.join(timeout + 0.5)

    if result["ok"] is None:
        # Per spec, no response is normal — most devices apply silently.
        return True, "Wysłano — brak odpowiedzi od urządzenia (normalne zachowanie wielu urządzeń PROFINET)"
    return result["ok"], result["msg"]


def send_dcp_set_ip(adapter_name: str, target_mac: str,
                    new_ip: str, new_mask: str, new_gateway: str,
                    permanent: bool = True) -> tuple[bool, str]:
    """Send DCP SET IP Parameters to a specific device (unicast by MAC).

    Args:
        adapter_name: Network adapter interface name.
        target_mac:   Target device MAC address.
        new_ip:       New IP address (e.g. '192.168.1.10').
        new_mask:     Subnet mask (e.g. '255.255.255.0').
        new_gateway:  Default gateway (e.g. '192.168.1.1' or '0.0.0.0').
        permanent:    If True, store permanently (qualifier=0x0001); else temporary (0x0000).

    Returns:
        (success: bool, message: str)
    """
    try:
        def _ip_bytes(s: str) -> bytes:
            parts = [int(x) for x in s.strip().split(".")]
            if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
                raise ValueError(f"Nieprawidłowy adres IP: {s!r}")
            return bytes(parts)

        ip_bytes      = _ip_bytes(new_ip)
        mask_bytes    = _ip_bytes(new_mask)
        gateway_bytes = _ip_bytes(new_gateway)

        # IP block value: IP(4) + Mask(4) + Gateway(4)
        ip_value  = ip_bytes + mask_bytes + gateway_bytes
        qualifier = 0x0001 if permanent else 0x0000

        block = _dcp_block(0x01, 0x02, ip_value, qualifier)
        frame = _build_dcp_set_frame(_next_xid(), block)
        src_mac = _adapter_src_mac(adapter_name)
        eth = Ether(dst=target_mac, type=PROFINET_ETHERTYPE)
        if src_mac:
            eth.src = src_mac
        pkt = eth / Raw(load=frame)

        return _dcp_set_send_and_listen(adapter_name, target_mac, pkt)

    except ValueError as e:
        return False, str(e)
    except Exception as e:
        log_exception(logger, "send_dcp_set_ip error", e)
        return False, f"Błąd: {e}"


def send_dcp_set_name(adapter_name: str, target_mac: str,
                      new_name: str,
                      permanent: bool = True) -> tuple[bool, str]:
    """Send DCP SET NameOfStation to a specific device (unicast by MAC).

    Args:
        adapter_name: Network adapter interface name.
        target_mac:   Target device MAC address.
        new_name:     New PROFINET station name (DNS-compatible, lowercase, max 240 chars).
        permanent:    If True, store permanently; else temporary.

    Returns:
        (success: bool, message: str)
    """
    try:
        import re as _re
        # Validate per PROFINET naming rules (IEC 61158-6-10 / DNS label rules)
        name = new_name.strip().lower()
        if len(name) > 240:
            return False, "Nazwa stacji jest za długa (maks. 240 znaków)"
        if name and not _re.fullmatch(
            r'[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*',
            name,
        ):
            return False, (
                "Nieprawidłowa nazwa stacji Profinet. "
                "Dozwolone znaki: a–z, 0–9, myślnik (-), kropka (.).\n"
                "Każdy segment musi zaczynać i kończyć się literą lub cyfrą."
            )

        qualifier  = 0x0001 if permanent else 0x0000
        block = _dcp_block(0x02, 0x02, name.encode("ascii"), qualifier)
        frame = _build_dcp_set_frame(_next_xid(), block)
        src_mac = _adapter_src_mac(adapter_name)
        eth = Ether(dst=target_mac, type=PROFINET_ETHERTYPE)
        if src_mac:
            eth.src = src_mac
        pkt = eth / Raw(load=frame)

        return _dcp_set_send_and_listen(adapter_name, target_mac, pkt)

    except Exception as e:
        log_exception(logger, "send_dcp_set_name error", e)
        return False, f"Błąd: {e}"


def build_dcp_identify_request():
    frame_id       = 0xFEFE
    service_id     = 0x05
    service_type   = 0x00
    xid            = 0x00000001
    response_delay = 0x0001
    data_length    = 0x0004
    all_selector   = struct.pack(">BBH", 0xFF, 0xFF, 0x0000)
    header = struct.pack(">HBBHHHH",
        frame_id,
        service_id, service_type,
        xid & 0xFFFF, (xid >> 16) & 0xFFFF,
        response_delay,
        data_length
    )
    return header + all_selector


def extract_profinet_payload(packet):
    raw = bytes(packet)
    idx = raw.find(b'\x88\x92')
    if idx == -1:
        return None, None
    src_mac = packet[Ether].src
    payload = raw[idx + 2:]
    return src_mac, payload


def parse_dcp_payload(src_mac, payload):
    try:
        offset = 0
        frame_id = struct.unpack_from(">H", payload, offset)[0]
        offset += 2
        if frame_id not in (0xFEFD, 0xFEFF):
            return None
        service_id   = payload[offset]
        service_type = payload[offset + 1]
        offset += 2
        if service_id != 0x05 or service_type != 0x01:
            return None
        offset += 4  # xid
        offset += 2  # response delay
        data_length = struct.unpack_from(">H", payload, offset)[0]
        offset += 2
        result = {
            "mac":             src_mac,
            "ip":              "",
            "name_of_station": "",
            "type_of_station": "",
            "vendor_id":       "",
            "device_id":       "",
            "device_role":     "",
            "device_instance": "",
            "device_family":   "",
            "firmware":        "",
            "protocol":        "Profinet DCP",
            "adapter":         "",
        }
        end = offset + data_length
        while offset + 4 <= end and offset + 4 <= len(payload):
            opt    = payload[offset]
            subopt = payload[offset + 1]
            length = struct.unpack_from(">H", payload, offset + 2)[0]
            offset += 4
            block_data = payload[offset:offset + length]
            offset += length + (length % 2)

            # Każdy blok DCP ma 2 bajty BlockInfo na początku.
            value = block_data[2:] if len(block_data) >= 2 else b""

            if (opt, subopt) == (0x01, 0x02):
                # IP Parameter: BlockInfo(2) + IP(4) + Mask(4) + Gateway(4)
                if len(block_data) >= 14:
                    ip_bytes = block_data[2:6]
                    result["ip"] = ".".join(str(b) for b in ip_bytes)
            elif (opt, subopt) == (0x02, 0x01):
                # Manufacturer specific (Type of Station)
                result["type_of_station"] = value.decode("ascii", errors="ignore").rstrip("\x00")
            elif (opt, subopt) == (0x02, 0x02):
                # Name Of Station
                result["name_of_station"] = value.decode("ascii", errors="ignore").rstrip("\x00")
            elif (opt, subopt) == (0x02, 0x03):
                # Device ID: BlockInfo(2) + VendorID(2) + DeviceID(2)
                if len(block_data) >= 6:
                    vendor = struct.unpack_from(">H", block_data, 2)[0]
                    device = struct.unpack_from(">H", block_data, 4)[0]
                    result["vendor_id"] = f"0x{vendor:04X}"
                    result["device_id"] = f"0x{device:04X}"
            elif (opt, subopt) == (0x02, 0x04):
                # Device Role: BlockInfo(2) + Role(1) + Reserved(1)
                if len(block_data) >= 3:
                    result["device_role"] = f"0x{block_data[2]:02X}"
            elif (opt, subopt) == (0x02, 0x05):
                # Device Options / Features: often contains HW and SW revision
                # Format varies; attempt to extract as ASCII string or hex.
                if len(block_data) > 2:
                    try:
                        text = value.decode("ascii", errors="ignore").strip()
                        if text:
                            result["device_family"] = text
                    except Exception:
                        pass
            elif (opt, subopt) == (0x02, 0x06):
                # Device Revision / Hardware Revision: typically HW version + SW version
                # Format: BlockInfo(2) + HWrev(1) + SWrev_prefix(1) + SWrev_main(1)
                # or just a string like "V1.0.0"
                if len(block_data) > 2:
                    try:
                        text = value.decode("ascii", errors="ignore").strip()
                        if text and not result.get("firmware"):
                            result["firmware"] = text
                    except Exception:
                        # Fallback: try as bytes HW.SW format
                        if len(block_data) >= 5:
                            hw = block_data[2]
                            sw_pre = block_data[3]
                            sw_main = block_data[4]
                            result["firmware"] = f"HW:{hw:02X} SW:{sw_pre:02X}.{sw_main:02X}"
            elif (opt, subopt) == (0x02, 0x07):
                # Device Instance: BlockInfo(2) + High(1) + Low(1)
                if len(block_data) >= 4:
                    result["device_instance"] = f"{block_data[2]}.{block_data[3]}"
            elif (opt, subopt) == (0x02, 0x08):
                # Vendor Specific: may contain firmware/version info
                if len(block_data) > 2 and not result.get("firmware"):
                    try:
                        text = value.decode("ascii", errors="ignore").strip()
                        if text:
                            result["firmware"] = text
                    except Exception:
                        pass

        return result if result["mac"] else None
    except Exception as e:
        log_exception(logger, "Blad parsowania DCP", e)
        return None


def send_dcp_identify(adapter_name, stop_event):
    try:
        payload = build_dcp_identify_request()
        src_mac = _adapter_src_mac(adapter_name)
        eth = Ether(dst=PROFINET_MULTICAST, type=PROFINET_ETHERTYPE)
        if src_mac:
            eth.src = src_mac
        pkt = eth / Raw(load=payload)
        sendp(pkt, iface=adapter_name, verbose=False)
    except Exception as e:
        log_exception(logger, f"Blad wysylania DCP na {adapter_name}", e)


def identify_dcp_device(adapter_name: str, target_mac: str, timeout: float = 2.5):
    """Send one DCP Identify-All and wait for Identify response from target MAC.

    Returns parsed device dict or None.
    """
    target_mac_norm = _normalize_mac(target_mac)
    found = {"device": None}
    stop = threading.Event()

    def handler(packet):
        if stop.is_set():
            return
        if not packet.haslayer(Ether):
            return
        src = _normalize_mac(packet[Ether].src)
        if src != target_mac_norm:
            return
        src_mac, payload = extract_profinet_payload(packet)
        if payload is None:
            return
        parsed = parse_dcp_payload(src_mac, payload)
        if parsed:
            parsed["adapter"] = adapter_name
            found["device"] = parsed
            stop.set()

    def run_sniffer():
        try:
            sniff(
                iface=adapter_name,
                prn=handler,
                stop_filter=lambda _p: stop.is_set(),
                timeout=timeout,
                # VLAN-tagged PN-DCP replies are possible; avoid restrictive BPF here.
                store=False,
            )
        except Exception as e:
            log_exception(logger, f"Blad verify Identify na {adapter_name}", e)
        finally:
            stop.set()

    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()

    time.sleep(0.12)
    send_dcp_identify(adapter_name, None)
    sniffer_thread.join(timeout + 0.5)
    return found["device"]


def listen_dcp_responses(adapter_name, callback, stop_event, burst_timeout=3):

    def handler(packet):
        if stop_event.is_set():
            return
        if not packet.haslayer(Ether):
            return
        src_mac, payload = extract_profinet_payload(packet)
        if payload is None:
            return
        result = parse_dcp_payload(src_mac, payload)
        if result:
            result["adapter"] = adapter_name
            callback(result)

    while not stop_event.is_set():
        try:
            sniff(
                iface=adapter_name,
                prn=handler,
                stop_filter=lambda x: stop_event.is_set(),
                timeout=burst_timeout,
                store=False
            )
        except Exception as e:
            log_exception(logger, f"Blad nasluchiwania DCP na {adapter_name}", e, ["not found"])
            break


def _dcp_scan_loop(adapter_name, callback, stop_event, repeat_interval=5):

    listen_thread = threading.Thread(
        target=listen_dcp_responses,
        args=(adapter_name, callback, stop_event),
        daemon=True
    )
    listen_thread.start()

    while not stop_event.is_set():
        send_dcp_identify(adapter_name, stop_event)
        for _ in range(int(repeat_interval / 0.2)):
            if stop_event.is_set():
                break
            time.sleep(0.2)

    listen_thread.join(timeout=4)


def start_dcp_scan(adapter_name, callback, stop_event):
    _dcp_scan_loop(adapter_name, callback, stop_event)


def start_dcp_scan_all(callback, stop_event):
    from scanner import get_adapters
    adapters = get_adapters()
    threads = []
    for adapter in adapters:
        name = adapter["name"]
        if not name:
            continue
        t = threading.Thread(
            target=_dcp_scan_loop,
            args=(name, callback, stop_event),
            daemon=True
        )
        t.start()
        threads.append(t)
    return threads