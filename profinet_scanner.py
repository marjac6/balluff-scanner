# profinet_scanner.py
import threading
import struct
from scapy.all import sendp, sniff, Ether, Raw
from debug_utils import get_logger, log_exception

logger = get_logger(__name__)

PROFINET_MULTICAST = "01:0e:cf:00:00:00"
PROFINET_ETHERTYPE = 0x8892


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
        pkt = Ether(dst=PROFINET_MULTICAST, type=PROFINET_ETHERTYPE) / Raw(load=payload)
        sendp(pkt, iface=adapter_name, verbose=False)
    except Exception as e:
        log_exception(logger, f"Blad wysylania DCP na {adapter_name}", e)


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

    import time

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