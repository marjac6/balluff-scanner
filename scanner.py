# scanner.py
# Logika skanowania ramek ARP - Balluff/BNI detector

# scanner.py
from scapy.all import sniff, ARP
from scapy.arch.windows import get_windows_if_list
import threading

KEYWORDS = ["balluff", "bni"]

# Prefiksy które ignorujemy — wirtualne/tunelowe/filtrowe
IGNORE_SUFFIXES = [
    "WFP Native MAC Layer LightWeight Filter",
    "WFP 802.3 MAC Layer LightWeight Filter",
    "QoS Packet Scheduler",
    "VirtualBox NDIS Light-Weight Filter",
    "Sentech Dfa Driver",
    "Native WiFi Filter Driver",
    "Virtual WiFi Filter Driver",
    "Npcap Packet Driver (NPCAP)",
    "Balluff Engineering Tool Network Driver",  # ← dodane
]

IGNORE_DESCRIPTIONS = [
    "WAN Miniport",
    "Teredo",
    "6to4",
    "IP-HTTPS",
    "Loopback",
    "Kernel Debug",
    "Bluetooth",
    "Tailscale",
    "Wintun",
    "Wi-Fi Direct",
]


def is_useful_adapter(adapter):
    """Filtruje tylko fizyczne/użyteczne adaptery."""
    desc = adapter.get("description", "")
    name = adapter.get("name", "")

    for suffix in IGNORE_SUFFIXES:
        if suffix in desc:
            return False
    for keyword in IGNORE_DESCRIPTIONS:
        if keyword in desc:
            return False

    return True


def get_adapters():
    """Zwraca przefiltrowaną listę adapterów."""
    adapters = []
    try:
        win_ifaces = get_windows_if_list()
        for iface in win_ifaces:
            adapter = {
                "name": iface.get("name", ""),
                "description": iface.get("description", ""),
                "ips": iface.get("ips", [])
            }
            if is_useful_adapter(adapter):
                adapters.append(adapter)
    except Exception as e:
        print(f"Błąd pobierania adapterów: {e}")
    return adapters


def check_arp_packet(packet, callback):
    """Sprawdza czy ramka ARP zawiera słowo kluczowe Balluff/BNI."""
    if packet.haslayer(ARP):
        raw = bytes(packet).lower()
        for keyword in KEYWORDS:
            if keyword.encode() in raw:
                info = {
                    "ip": packet[ARP].psrc,
                    "mac": packet[ARP].hwsrc,
                    "keyword": keyword.upper(),
                    "adapter": getattr(packet, "sniffed_on", "?")
                }
                callback(info)
                return


def start_scan(adapter_name, callback, stop_event):
    """Uruchamia nasłuchiwanie na wybranym adapterze."""
    def handler(packet):
        if stop_event.is_set():
            return
        check_arp_packet(packet, callback)

    try:
        sniff(
            iface=adapter_name,
            filter="arp",
            prn=handler,
            stop_filter=lambda x: stop_event.is_set(),
            store=False
        )
    except Exception as e:
        print(f"Błąd skanowania {adapter_name}: {e}")


def start_scan_all(callback, stop_event):
    """Uruchamia nasłuchiwanie na wszystkich użytecznych adapterach."""
    adapters = get_adapters()
    threads = []
    for adapter in adapters:
        name = adapter["name"]
        if not name:
            continue
        t = threading.Thread(
            target=start_scan,
            args=(name, callback, stop_event),
            daemon=True
        )
        t.start()
        threads.append(t)
    return threads