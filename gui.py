# gui.py
import sys
import os
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import webbrowser
import string
import time
from svglib.svglib import svg2rlg
from reportlab.graphics import renderPM
from PIL import Image, ImageTk
from io import BytesIO
from version import __version__
from scanner import get_adapters, start_scan, start_active_scan, send_arp_probe
from profinet_scanner import start_dcp_scan_all, start_dcp_scan
from lldp_scanner import start_lldp_scan_all, start_lldp_scan
from ethercat_scanner import start_ecat_scan_all, start_ecat_scan
from ethernetip_scanner import probe_enip_device
from modbus_scanner import probe_modbus_device
from vendor_registry import lookup_vendor_name, lookup_vendor_from_mac
from debug_utils import get_logger

REPO_URL = "https://github.com/marjac6/ProtocolHarbor"
ADAPTER_REFRESH_IDLE_MS = 5000
ADAPTER_REFRESH_SCANNING_MS = 15000
PROBE_COOLDOWN_SECONDS = 15
LOGGER = get_logger(__name__)


def _resource_path(filename):
    base = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(base, filename)


def _load_changelog():
    try:
        with open(_resource_path("CHANGELOG.md"), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "(CHANGELOG.md not found)"

CHANGELOG = _load_changelog()


class App:
    def __init__(self, root):
        self.root = root
        self.root.title(f"ProtocolHarbor  v{__version__}")
        self.root.geometry("1020x640")
        self.root.resizable(True, True)
        self.root.minsize(720, 480)
        self.stop_event    = threading.Event()
        self.scanning      = False
        self.found_devices = []
        self.adapters = []
        self._adapter_signature = ()
        self._all_vendors_label = "Wszyscy producenci"
        self._probe_lock = threading.Lock()
        self._scheduled_protocol_probes = {}
        # ARP conflict evidence (RFC 5227 / Wireshark style):
        # key = (adapter, ip)  →  set of MACs seen as ARP sender for that IP.
        # A conflict exists when the set has more than one distinct MAC.
        self._arp_ip_mac: dict = {}
        self._arp_conflict_logged: set = set()
        self.vendor_filter_var = tk.StringVar(value=self._all_vendors_label)

        def svg_to_tkimg(svg_path, size=(16, 16)):
            drawing = svg2rlg(svg_path)
            if drawing is None:
                return None
            buf = BytesIO()
            renderPM.drawToFile(drawing, buf, fmt="PNG")
            buf.seek(0)
            img = Image.open(buf).resize(size, Image.Resampling.LANCZOS)
            return ImageTk.PhotoImage(img)

        self.github_logo = svg_to_tkimg(_resource_path("github.svg"))
        self._build_ui()
        self._refresh_adapters(force_log=True)
        self._schedule_adapter_refresh()

    def _build_ui(self):
        # -- adapter selector --
        top = tk.LabelFrame(self.root, text="Adapter sieciowy", padx=8, pady=6)
        top.pack(fill="x", padx=10, pady=(10, 4))

        tk.Label(top, text="Skanuj:").grid(row=0, column=0, sticky="w")
        self.adapter_var = tk.StringVar(value="Wszystkie adaptery")
        self.adapter_cb  = ttk.Combobox(top, textvariable=self.adapter_var,
                                         width=55, state="readonly")
        self.adapter_cb.grid(row=0, column=1, padx=8)

        self.btn_scan = tk.Button(
            top, text="▶  Skanuj", width=12,
            bg="#2e7d32", fg="white", font=("Segoe UI", 9, "bold"),
            command=self.toggle_scan,
        )
        self.btn_scan.grid(row=0, column=2, padx=4)

        self.btn_clear = tk.Button(top, text="🗑  Wyczyść", width=12,
                                    command=self.clear_results)
        self.btn_clear.grid(row=0, column=3, padx=4)

        # -- status bar --
        self.status_var = tk.StringVar(value="Gotowy")
        tk.Label(self.root, textvariable=self.status_var,
                 anchor="w", relief="sunken", font=("Segoe UI", 8)
                 ).pack(fill="x", padx=10, pady=(0, 4))

        # -- results table --
        # Kolumny:
        #   ip, mac, name        — wspólne
        #   protocol             — ARP / Profinet DCP / EtherCAT
        #   vendor_id            — VendorID hex  (wszystkie protokoły)
        #   device_id            — DeviceID / ProductCode / ProductName (zależnie od protokołu)
        #   version              — SW Version (EtherCAT) / Revision (Profinet)
        #   adapter
        table_frame = tk.LabelFrame(self.root, text="Znalezione urządzenia",
                                     padx=8, pady=6)
        table_frame.pack(fill="both", expand=True, padx=10, pady=4)

        filter_bar = tk.Frame(table_frame)
        filter_bar.pack(fill="x", pady=(0, 6))

        tk.Label(filter_bar, text="Filtr producenta:", font=("Segoe UI", 8)).pack(side="left", padx=(0, 6))
        self.vendor_filter_cb = ttk.Combobox(
            filter_bar,
            textvariable=self.vendor_filter_var,
            width=34,
            state="readonly",
        )
        self.vendor_filter_cb.pack(side="left")
        self.vendor_filter_cb.bind("<<ComboboxSelected>>", self._on_vendor_filter_change)
        self._refresh_vendor_filter_options()

        cols = ("ip", "mac", "producer", "module_name", "device_desc", "protocol", "vendor_id", "device_id", "version", "adapter")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)

        self.tree.heading("ip",          text="Adres IP")
        self.tree.heading("mac",         text="Adres MAC")
        self.tree.heading("producer",    text="Producent")
        self.tree.heading("module_name", text="Nazwa modułu")
        self.tree.heading("device_desc", text="Opis urządzenia")
        self.tree.heading("protocol",    text="Protokół")
        self.tree.heading("vendor_id",   text="ID producenta")
        self.tree.heading("device_id",   text="ID urządzenia")
        self.tree.heading("version",     text="Wersja")
        self.tree.heading("adapter",     text="Adapter")

        self.tree.column("ip",          width=110)
        self.tree.column("mac",         width=140)
        self.tree.column("producer",    width=140)
        self.tree.column("module_name", width=160)
        self.tree.column("device_desc", width=160)
        self.tree.column("protocol",    width=105)
        self.tree.column("vendor_id",   width=100)
        self.tree.column("device_id",   width=120)
        self.tree.column("version",     width=85)
        self.tree.column("adapter",     width=155)

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.tree.tag_configure("ip_conflict", background="#fff3cd", foreground="#7c5c00")

        # -- log --
        log_frame = tk.LabelFrame(self.root, text="Log", padx=8, pady=4)
        log_frame.pack(fill="x", padx=10, pady=(4, 2))

        self.log = scrolledtext.ScrolledText(log_frame, height=5,
                                              font=("Consolas", 8), state="disabled")
        self.log.pack(fill="x")

        # -- bottom bar --
        bottom = tk.Frame(self.root, bg="#f0f0f0", bd=1, relief="sunken")
        bottom.pack(fill="x", padx=0, pady=(2, 0))

        tk.Label(bottom, text=f"v{__version__}",
                 font=("Consolas", 7), fg="#888", bg="#f0f0f0").pack(side="left", padx=8)

        tk.Button(bottom, text="zmiany",
                  font=("Segoe UI", 7), fg="#555", bg="#f0f0f0",
                  relief="flat", cursor="hand2",
                  command=self._show_changelog).pack(side="left", padx=2)

        repo_frame = tk.Frame(bottom, bg="#f0f0f0")
        repo_frame.pack(side="right", padx=8)
        if self.github_logo:
            tk.Label(repo_frame, image=self.github_logo, bg="#f0f0f0").pack(side="left")
        lnk = tk.Label(repo_frame, text="github: ProtocolHarbor",
                        font=("Segoe UI", 7, "underline"), fg="#0969da",
                        bg="#f0f0f0", cursor="hand2")
        lnk.pack(side="left", padx=2)
        lnk.bind("<Button-1>", lambda e: webbrowser.open(REPO_URL))

    def _show_changelog(self):
        win = tk.Toplevel(self.root)
        win.title("Changelog")
        win.geometry("480x300")
        win.resizable(False, False)
        st = scrolledtext.ScrolledText(win, font=("Consolas", 8), state="normal")
        st.pack(fill="both", expand=True, padx=8, pady=8)
        st.insert("1.0", CHANGELOG)
        st.configure(state="disabled")

    def _on_vendor_filter_change(self, _event=None):
        self._rebuild_table()
        self.log_message(f"Filtr producenta: {self.vendor_filter_var.get()}")

    def _producer_for_info(self, info):
        protocol = info.get("protocol") or info.get("type", "ARP")
        vendor_id = info.get("vendor_id", "")
        mac = info.get("mac", "")

        def _mac_fallback():
            """Resolve producer from MAC OUI when nothing else is known."""
            return lookup_vendor_from_mac(mac) if mac else ""

        def _clean(value: str) -> str:
            """Return value unless it looks like a raw OUI prefix (e.g. '00:19:31')."""
            from vendor_registry import _looks_like_oui
            return "" if _looks_like_oui(value) else value

        if protocol == "EtherCAT":
            return _clean(info.get("vendor_name", "")) or lookup_vendor_name(vendor_id, protocol="ethercat") or _mac_fallback()
        if protocol == "Profinet DCP":
            return _clean(info.get("vendor_name", "")) or lookup_vendor_name(vendor_id, protocol="profinet") or _mac_fallback()
        if protocol == "EtherNet/IP":
            return (_clean(info.get("producer", ""))
                    or _clean(info.get("vendor_name", ""))
                    or lookup_vendor_name(vendor_id, protocol="ethernet/ip")
                    or _mac_fallback())
        if protocol == "Modbus TCP":
            return (_clean(info.get("producer", ""))
                    or _clean(info.get("vendor_name", ""))
                    or _mac_fallback())
        return _clean(info.get("vendor_name", "")) or _clean(info.get("keyword", "")) or _mac_fallback()

    def _refresh_vendor_filter_options(self):
        current = self.vendor_filter_var.get() or self._all_vendors_label
        vendors = sorted({self._producer_for_info(info) for info in self.found_devices if self._producer_for_info(info)})
        values = [self._all_vendors_label] + vendors
        self.vendor_filter_cb["values"] = values
        if current in values:
            self.vendor_filter_var.set(current)
        else:
            self.vendor_filter_var.set(self._all_vendors_label)

    def _device_to_row(self, info):
        protocol = info.get("protocol") or "ARP"
        producer = self._producer_for_info(info)

        if protocol == "EtherCAT":
            module_name = info.get("product_name", "") or info.get("name", "")
            device_id   = info.get("product_code", "")
            version     = info.get("sw_version", "")
            # Pokaż dodatkową nazwę (tę, która nie trafiła do product_name)
            sii = info.get("sii_name", "")
            sdo = info.get("device_name_sdo", "")
            device_desc = sdo if sdo and sdo != module_name else (sii if sii and sii != module_name else "")
        elif protocol == "EtherNet/IP":
            module_name = (
                info.get("product_name")
                or info.get("module_name")
                or info.get("model_name")
                or info.get("name_of_station")
                or info.get("type_of_station")
                or ""
            )
            device_id = info.get("device_id", "")
            version = info.get("version", "") or info.get("firmware", "")
            device_desc = ""
        elif protocol == "Modbus TCP":
            module_name = (
                info.get("product_name")
                or info.get("model_name")
                or info.get("module_name")
                or info.get("name_of_station")
                or info.get("type_of_station")
                or ""
            )
            device_id = info.get("device_id", "")
            version = info.get("version", "") or info.get("firmware", "")
            # model_name (obj 0x05) jako uzupełnienie product_name (obj 0x04)
            model = info.get("model_name", "")
            device_desc = model if model and model != module_name else ""
        elif protocol == "Profinet DCP":
            module_name = (
                info.get("name_of_station")
                or info.get("product_name")
                or info.get("module_name")
                or info.get("model_name")
                or info.get("lldp_model")
                or info.get("lldp_system_name")
                or ""
            )
            device_id = info.get("device_id", "")
            version = info.get("firmware", "") or info.get("version", "")
            # type_of_station = DeviceVendorValue (opis/typ urządzenia od producenta)
            device_desc = (
                info.get("type_of_station", "")
                or info.get("lldp_system_description", "")
                or ""
            )
        else:
            module_name = (
                info.get("product_name")
                or info.get("module_name")
                or info.get("model_name")
                or info.get("name_of_station")
                or info.get("type_of_station")
                or ""
            )
            device_id = info.get("device_id", "")
            version   = (
                info.get("sw_version")
                or info.get("firmware")
                or info.get("version")
                or ""
            )
            device_desc = info.get("lldp_system_description", "")

        return (
            info.get("ip", ""),
            info.get("mac", ""),
            producer,
            module_name,
            device_desc,
            protocol,
            info.get("vendor_id", ""),
            device_id,
            version,
            info.get("adapter", "?"),
        )

    def _is_visible(self, info):
        selected = self.vendor_filter_var.get() or self._all_vendors_label
        if selected == self._all_vendors_label:
            return True
        return self._producer_for_info(info) == selected

    def _rebuild_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for info in self.found_devices:
            if self._is_visible(info):
                conflict = self._is_ip_conflict(
                    info.get("adapter", "?"),
                    info.get("ip", ""),
                )
                tags = ("ip_conflict",) if conflict else ()
                self.tree.insert("", "end", values=self._device_to_row(info), tags=tags)

    def _hex_to_text_details(self, hex_value):
        text = str(hex_value or "").strip()
        if not text:
            return ""

        if text.lower().startswith("0x"):
            text = text[2:]

        if not text:
            return ""

        if len(text) % 2 == 1:
            text = "0" + text

        try:
            data = bytes.fromhex(text)
        except ValueError:
            return ""

        dec_value = int.from_bytes(data, byteorder="big", signed=False)
        ascii_preview = "".join(chr(b) if chr(b) in string.printable and b >= 32 else "." for b in data)
        return f"dec={dec_value}, ascii='{ascii_preview}'"

    def _log_ecat_diagnostics(self, info):
        LOGGER.debug("--- Diagnostyka EtherCAT ---")
        ordered_keys = [
            "adapter",
            "slave_index",
            "slave_count",
            "vendor_name",
            "vendor_id",
            "product_code",
            "revision",
            "serial",
            "product_name",
            "product_name_source",
            "device_name_sdo",
            "sii_name",
            "sw_version",
            "protocol",
        ]

        for key in ordered_keys:
            if key in info:
                LOGGER.debug("%s: %s", key, info.get(key, ""))

        for key in ("vendor_id", "product_code", "revision", "serial"):
            details = self._hex_to_text_details(info.get(key, ""))
            if details:
                LOGGER.debug("%s_decoded: %s", key, details)

        LOGGER.debug("----------------------------")

    def _adapter_sig(self, adapters):
        return tuple(
            (a.get("name", ""), a.get("description", ""), tuple(a.get("ips", [])))
            for a in adapters
        )

    def _adapter_label(self, adapter):
        ips = ", ".join(adapter.get("ips", [])) or "brak IP"
        return f"{adapter.get('description', '')}  [{ips}]"

    def _get_selected_adapter_index(self):
        selected_value = self.adapter_var.get().strip()
        if not selected_value or selected_value == "Wszystkie adaptery":
            return -1

        for index, adapter in enumerate(self.adapters):
            if self._adapter_label(adapter) == selected_value:
                return index
        return -1

    def _refresh_adapters(self, force_log=False):
        current_value = self.adapter_var.get()
        current_index = self._get_selected_adapter_index()
        new_adapters = get_adapters()
        new_sig = self._adapter_sig(new_adapters)
        if not force_log and new_sig == self._adapter_signature:
            return

        self.adapters = new_adapters
        self._adapter_signature = new_sig

        names = ["Wszystkie adaptery"] + [self._adapter_label(a) for a in self.adapters]
        self.adapter_cb["values"] = names

        if current_value in names:
            self.adapter_cb.current(names.index(current_value))
        else:
            self.adapter_cb.current(0)
            if self.scanning and current_index > 0:
                self.log_message("Selected adapter disconnected/removed. Stopping scan.")
                self._stop_scan()

        LOGGER.debug("Adapters updated: %s available.", len(self.adapters))

    def _schedule_adapter_refresh(self):
        self._refresh_adapters(force_log=False)
        interval = ADAPTER_REFRESH_SCANNING_MS if self.scanning else ADAPTER_REFRESH_IDLE_MS
        self.root.after(interval, self._schedule_adapter_refresh)

    def log_message(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def on_device_found(self, info):
        self.root.after(0, self._add_device, info)

    def on_profinet_found(self, info):
        self.root.after(0, self._add_profinet_device, info)

    def on_ecat_found(self, info):
        self.root.after(0, self._add_ecat_device, info)

    def on_enip_found(self, info):
        self.root.after(0, self._add_enip_device, info)

    def on_modbus_found(self, info):
        self.root.after(0, self._add_modbus_device, info)

    def on_lldp_found(self, info):
        self.root.after(0, self._merge_lldp_info, info)

    def _merge_lldp_info(self, info):
        mac = (info.get("mac") or "").lower()
        ip  = info.get("ip", "")
        if not mac and not ip:
            return

        dev = self._find_device(ip, mac)
        if dev is None:
            # No existing entry yet — create a stub so LLDP data is not lost
            dev, _ = self._ensure_device(ip, mac, "ARP", "?")

        changed = False
        changed |= self._fill_field(dev, "ip",              ip)
        changed |= self._fill_field(dev, "vendor_name",     info.get("producer"))
        changed |= self._fill_field(dev, "firmware",        info.get("firmware"))
        changed |= self._fill_field(dev, "version",         info.get("firmware"))
        # Keep LLDP identity fields separate from Profinet DCP identity
        # to avoid replacing correct DCP module naming.
        changed |= self._fill_field(dev, "lldp_model",              info.get("model"))
        changed |= self._fill_field(dev, "lldp_system_name",        info.get("system_name"))
        changed |= self._fill_field(dev, "lldp_system_description", info.get("system_description"))
        changed |= self._fill_field(dev, "product_name",            info.get("model"))

        if changed:
            self._refresh_vendor_filter_options()
            self._rebuild_table()
            self.log_message(f"Uzupełniono dane przez LLDP: {ip or mac}")

    def _queue_protocol_probe(self, protocol, ip, adapter_name, probe_func, callback):
        key = (protocol, ip)
        now = time.monotonic()
        with self._probe_lock:
            last_run = self._scheduled_protocol_probes.get(key, 0.0)
            if (now - last_run) < PROBE_COOLDOWN_SECONDS:
                return
            self._scheduled_protocol_probes[key] = now

        threading.Thread(
            target=probe_func,
            args=(ip, adapter_name, callback),
            daemon=True,
        ).start()

    def _schedule_identity_probes(self, info):
        ip = (info.get("ip") or "").strip()
        if not ip or ip == "0.0.0.0":
            return

        adapter_name = info.get("adapter", "?")
        self._queue_protocol_probe("EtherNet/IP", ip, adapter_name, probe_enip_device, self.on_enip_found)
        self._queue_protocol_probe("Modbus TCP", ip, adapter_name, probe_modbus_device, self.on_modbus_found)

    _PROTOCOL_PAYLOAD_FIELDS = (
        "vendor_name",
        "producer",
        "vendor_id",
        "device_id",
        "version",
        "firmware",
        "product_name",
        "module_name",
        "model_name",
        "name_of_station",
        "type_of_station",
        "lldp_system_description",
        "device_role",
        "device_instance",
    )

    # ── ARP conflict detection (RFC 5227 / Wireshark style) ──────────────────

    def _record_arp(self, adapter: str, ip: str, mac: str) -> bool:
        """Record one ARP observation (adapter, ip) → mac.
        Returns True the first time a second distinct MAC appears for that IP
        (i.e. the moment a new conflict is discovered).
        """
        key = ((adapter or "?").strip(), ip.strip())
        macs = self._arp_ip_mac.setdefault(key, set())
        was_conflicted = len(macs) > 1
        macs.add(mac.lower().strip())
        is_conflicted = len(macs) > 1
        return is_conflicted and not was_conflicted  # True only on the first new conflict

    def _is_ip_conflict(self, adapter: str, ip: str) -> bool:
        """Return True if ARP evidence shows >1 MAC for this (adapter, ip)."""
        if not ip or ip == "0.0.0.0":
            return False
        key = ((adapter or "?").strip(), ip.strip())
        return len(self._arp_ip_mac.get(key, set())) > 1

    # ── Device lookup / creation ──────────────────────────────────────────────

    def _find_device(self, ip, mac):
        """Return existing non-EtherCAT device matching MAC or IP, or None."""
        mac_n = (mac or "").lower().strip()
        ip_n  = (ip  or "").strip()
        for dev in self.found_devices:
            if dev.get("protocol") == "EtherCAT":
                continue
            if mac_n and (dev.get("mac") or "").lower() == mac_n:
                return dev
            if ip_n and ip_n != "0.0.0.0" and dev.get("ip") == ip_n:
                return dev
        return None

    def _ensure_device(self, ip, mac, protocol, adapter):
        """Find existing device or create a new stub. Returns (device, is_new)."""
        dev = self._find_device(ip, mac)
        if dev is not None:
            return dev, False
        dev = {
            "ip":       ip or "",
            "mac":      mac or "",
            "protocol": protocol,
            "adapter":  adapter or "?",
        }
        self.found_devices.append(dev)
        return dev, True

    def _update_protocol(self, device, protocol):
        """Set active protocol; ARP never downgrades an already identified protocol."""
        current = device.get("protocol", "ARP")
        if protocol == "ARP":
            if not current:
                device["protocol"] = "ARP"
                return True
            return False
        if current != protocol:
            device["protocol"] = protocol
            return True
        return False

    def _reset_protocol_payload(self, device):
        """Drop stale protocol-dependent fields before applying a new protocol payload."""
        changed = False
        for field in self._PROTOCOL_PAYLOAD_FIELDS:
            if field in device:
                device.pop(field, None)
                changed = True
        return changed

    def _fill_field(self, device, field, value):
        """Fill device[field] only if currently empty. Returns True if changed."""
        if value and not device.get(field):
            device[field] = value
            return True
        return False

    def _overwrite_field(self, device, field, value):
        """Overwrite device[field] with value if value is non-empty. Returns True if changed."""
        if value and device.get(field) != value:
            device[field] = value
            return True
        return False

    # ── Device adders ─────────────────────────────────────────────────────────

    def _add_device(self, info):
        """ARP discovery: find-or-create device entry, merge ARP data."""
        info = dict(info)
        ip  = (info.get("ip")  or "").strip()
        mac = (info.get("mac") or "").strip()
        if not ip and not mac:
            return

        # Record ARP evidence BEFORE any merging.
        new_conflict = False
        if ip and ip not in ("0.0.0.0", "255.255.255.255") and mac:
            adapter = (info.get("adapter") or "?").strip()
            new_conflict = self._record_arp(adapter, ip, mac)

        dev, is_new = self._ensure_device(ip, mac, "ARP", info.get("adapter", "?"))

        changed = False
        changed |= self._fill_field(dev, "ip",          ip)
        changed |= self._fill_field(dev, "mac",         mac)
        changed |= self._fill_field(dev, "vendor_name", info.get("vendor_name") or info.get("keyword"))
        changed |= self._fill_field(dev, "adapter",     info.get("adapter"))

        if is_new or new_conflict:
            self._refresh_vendor_filter_options()
            self._rebuild_table()
            if is_new:
                self.log_message(f"Wykryto urządzenie: {ip or mac}")
            if new_conflict:
                adapter = (info.get("adapter") or "?").strip()
                macs = sorted(self._arp_ip_mac.get((adapter, ip), set()))
                key = (adapter, ip)
                if key not in self._arp_conflict_logged:
                    self._arp_conflict_logged.add(key)
                    self.log_message(
                        f"[UWAGA] Konflikt IP w ARP ({adapter}): {ip} — "
                        f"wiele MAC: {', '.join(macs)}"
                    )
        elif changed:
            self._refresh_vendor_filter_options()
            self._rebuild_table()

        # Re-probe while scanning (with cooldown) so protocol switches are picked up without restart.
        self._schedule_identity_probes({"ip": dev.get("ip", ""), "adapter": dev.get("adapter", "?")})

    def _add_profinet_device(self, info):
        info = dict(info)
        ip  = (info.get("ip")  or "").strip()
        mac = (info.get("mac") or "").strip()

        dev, is_new = self._ensure_device(ip, mac, "Profinet DCP", info.get("adapter", "?"))
        protocol_changed = self._update_protocol(dev, "Profinet DCP")

        changed = is_new or protocol_changed
        if protocol_changed:
            changed |= self._reset_protocol_payload(dev)

        changed |= self._overwrite_field(dev, "ip",      ip)
        changed |= self._fill_field(dev,      "mac",     mac)
        changed |= self._overwrite_field(dev, "adapter", info.get("adapter"))

        w = self._overwrite_field
        changed |= w(dev, "name_of_station", info.get("name_of_station"))
        changed |= w(dev, "type_of_station", info.get("type_of_station"))
        changed |= w(dev, "vendor_id",       info.get("vendor_id"))
        changed |= w(dev, "device_id",       info.get("device_id"))
        changed |= w(dev, "device_role",     info.get("device_role"))
        changed |= w(dev, "device_instance", info.get("device_instance"))
        changed |= w(dev, "firmware",        info.get("firmware"))

        if protocol_changed or not dev.get("vendor_name"):
            vn = info.get("vendor_name") or lookup_vendor_name(info.get("vendor_id", ""), protocol="profinet")
            if vn:
                dev["vendor_name"] = vn
                changed = True

        if changed:
            self._refresh_vendor_filter_options()
            self._rebuild_table()
        if is_new:
            self.log_message(f"Wykryto urządzenie Profinet DCP: {ip}")
        self._schedule_identity_probes({"ip": dev.get("ip", ""), "adapter": dev.get("adapter", "?")})

    def _add_ecat_device(self, info):
        """
        Deduplikacja EtherCAT po (adapter, vendor_id, product_name).
                Wyświetla:
                    name       = product_name (np. "IO Module XG5-538-0B5-R067")
          vendor_id  = hex VID
          device_id  = product_code (prawdziwy EtherCAT Product Code)
          version    = sw_version   (np. "1.3.1")
        """
        product_name = info.get("product_name", "")
        sw_version   = info.get("sw_version",   "")
        vendor_id    = info.get("vendor_id",    "")
        product_code = info.get("product_code", "")

        # Klucz deduplikacji uwzględnia pozycję slave'a w łańcuchu EtherCAT.
        # Dwa identyczne moduły mają ten sam vendor_id i product_name, ale różny slave_index.
        slave_index = info.get("slave_index", -1)
        key = (info.get("adapter", ""), vendor_id, product_name, slave_index)
        for d in self.found_devices:
            if d.get("protocol") != "EtherCAT":
                continue
            dk = (d.get("adapter",""), d.get("vendor_id",""), d.get("product_name",""), d.get("slave_index",-1))
            if dk == key:
                return

        info = dict(info)
        info["protocol"] = "EtherCAT"
        info["vendor_name"] = info.get("vendor_name", "") or lookup_vendor_name(vendor_id, protocol="ethercat")

        self.found_devices.append(info)
        self._refresh_vendor_filter_options()
        if self._is_visible(info):
            self.tree.insert("", "end", values=self._device_to_row(info))
        self.log_message(f"Wykryto urządzenie EtherCAT: {product_name or info.get('ip', '?')}")
        self._log_ecat_diagnostics(info)

    def _add_enip_device(self, info):
        info = dict(info)
        ip  = (info.get("ip")  or "").strip()
        mac = (info.get("mac") or "").strip()

        dev, is_new = self._ensure_device(ip, mac, "EtherNet/IP", info.get("adapter", "?"))
        protocol_changed = self._update_protocol(dev, "EtherNet/IP")

        changed = is_new or protocol_changed
        if protocol_changed:
            changed |= self._reset_protocol_payload(dev)

        changed |= self._overwrite_field(dev, "ip",      ip)
        changed |= self._fill_field(dev,      "mac",     mac)
        changed |= self._overwrite_field(dev, "adapter", info.get("adapter"))

        w = self._overwrite_field
        changed |= w(dev, "device_id",    info.get("device_id"))
        changed |= w(dev, "vendor_id",    info.get("vendor_id"))
        changed |= w(dev, "version",      info.get("version"))
        changed |= w(dev, "product_name", info.get("product_name") or info.get("module_name"))

        # Producer priority: EIP payload > ODVA map > keep existing
        if protocol_changed or not dev.get("vendor_name"):
            eip_producer = info.get("producer") or info.get("vendor_name")
            if eip_producer:
                dev["vendor_name"] = eip_producer
                dev["producer"]    = eip_producer
                changed = True
            else:
                mapped = lookup_vendor_name(info.get("vendor_id", ""), protocol="ethernet/ip")
                if mapped:
                    dev["vendor_name"] = mapped
                    dev["producer"]    = mapped
                    changed = True

        if changed:
            self._refresh_vendor_filter_options()
            self._rebuild_table()
        if is_new:
            self.log_message(f"Wykryto urządzenie EtherNet/IP: {ip}")

    def _add_modbus_device(self, info):
        info = dict(info)
        ip  = (info.get("ip")  or "").strip()
        mac = (info.get("mac") or "").strip()

        dev, is_new = self._ensure_device(ip, mac, "Modbus TCP", info.get("adapter", "?"))
        protocol_changed = self._update_protocol(dev, "Modbus TCP")

        changed = is_new or protocol_changed
        if protocol_changed:
            changed |= self._reset_protocol_payload(dev)

        changed |= self._overwrite_field(dev, "ip",      ip)
        changed |= self._fill_field(dev,      "mac",     mac)
        changed |= self._overwrite_field(dev, "adapter", info.get("adapter"))

        w = self._overwrite_field
        changed |= w(dev, "device_id",    info.get("device_id"))
        changed |= w(dev, "version",      info.get("version"))
        changed |= w(dev, "product_name",
                    info.get("product_name") or info.get("module_name") or info.get("model_name"))

        if protocol_changed or not dev.get("vendor_name"):
            producer = self._producer_for_info({**dev, **info})
            if producer:
                dev["vendor_name"] = producer
                dev["producer"]    = producer
                changed = True

        if changed:
            self._refresh_vendor_filter_options()
            self._rebuild_table()
        if is_new:
            self.log_message(f"Wykryto urządzenie Modbus TCP: {ip}")

    # ── Scan control ──────────────────────────────────────────────────────────

    def toggle_scan(self):
        if not self.scanning:
            self._start_scan()
        else:
            self._stop_scan()

    def _start_scan(self):
        self._refresh_adapters(force_log=False)
        self.scanning = True
        self.stop_event.clear()
        with self._probe_lock:
            self._scheduled_protocol_probes.clear()
        self.btn_scan.config(text="⏹  Zatrzymaj", bg="#c62828")
        self.status_var.set("⏳ Skanowanie w toku…")

        selected_index = self._get_selected_adapter_index()

        if selected_index < 0:
            self.log_message("Start skanowania ARP + Profinet DCP + EtherCAT oraz identyfikacji EtherNet/IP i Modbus TCP na wszystkich adapterach…")
            threading.Thread(
                target=start_active_scan,
                args=(self.on_device_found, self.stop_event), daemon=True).start()
            threading.Thread(
                target=start_dcp_scan_all,
                args=(self.on_profinet_found, self.stop_event), daemon=True).start()
            threading.Thread(
                target=start_lldp_scan_all,
                args=(self.on_lldp_found, self.stop_event), daemon=True).start()
            threading.Thread(
                target=start_ecat_scan_all,
                args=(self.on_ecat_found, self.stop_event), daemon=True).start()
        else:
            if selected_index >= len(self.adapters):
                self.log_message("Selected adapter is no longer available. Refreshing list.")
                self._refresh_adapters(force_log=True)
                self._stop_scan()
                return

            adapter = self.adapters[selected_index]
            self.log_message(
                f"Start skanowania ARP + Profinet DCP + EtherCAT oraz identyfikacji EtherNet/IP i Modbus TCP na: {adapter['description']}…")
            threading.Thread(
                target=start_scan,
                args=(adapter["name"], self.on_device_found, self.stop_event), daemon=True).start()
            threading.Thread(
                target=send_arp_probe,
                args=(adapter["name"], self.stop_event), daemon=True).start()
            threading.Thread(
                target=start_dcp_scan,
                args=(adapter["name"], self.on_profinet_found, self.stop_event), daemon=True).start()
            threading.Thread(
                target=start_lldp_scan,
                args=(adapter["name"], self.on_lldp_found, self.stop_event), daemon=True).start()
            threading.Thread(
                target=start_ecat_scan,
                args=(adapter["name"], self.on_ecat_found, self.stop_event), daemon=True).start()

    def _stop_scan(self):
        self.scanning = False
        self.stop_event.set()
        self.btn_scan.config(text="▶  Skanuj", bg="#2e7d32")
        self.status_var.set("Zatrzymano.")
        self.log_message("Skan zatrzymany.")

    def clear_results(self):
        self.found_devices.clear()
        with self._probe_lock:
            self._scheduled_protocol_probes.clear()
        self._arp_ip_mac.clear()
        self._arp_conflict_logged.clear()
        self._refresh_vendor_filter_options()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.log_message("Wyniki wyczyszczone.")