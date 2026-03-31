# gui.py
import sys
import os
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import webbrowser
import string
import time
import ipaddress
import subprocess
import re
from svglib.svglib import svg2rlg
from reportlab.graphics import renderPM
from PIL import Image, ImageTk
from io import BytesIO
from version import __version__
from scanner import get_adapters, start_scan, start_active_scan, send_arp_probe
from profinet_scanner import (
    start_dcp_scan_all,
    start_dcp_scan,
    send_dcp_set_ip,
    send_dcp_set_name,
    identify_dcp_device,
)
from lldp_scanner import start_lldp_scan_all, start_lldp_scan
from ethercat_scanner import start_ecat_scan_all, start_ecat_scan, switch_balluff_xg_to_eip
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
        self._tree_row_device_map: dict = {}
        self._tree_row_ip_state_map: dict = {}
        self._tree_overlay_widgets: dict = {}
        self._tree_overlay_refresh_pending = False
        self.vendor_filter_var = tk.StringVar(value=self._all_vendors_label)
        self._adapter_networks_by_mac: dict = {}

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
        self.adapter_cb.bind("<<ComboboxSelected>>", self._on_adapter_selected)

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
        main_pane = tk.PanedWindow(self.root, orient="vertical", sashrelief="raised", sashwidth=6, bd=0)
        main_pane.pack(fill="both", expand=True, padx=10, pady=4)

        table_frame = tk.LabelFrame(main_pane, text="Znalezione urządzenia",
                         padx=8, pady=6)
        main_pane.add(table_frame, minsize=260)

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

        tk.Label(filter_bar, text="│", font=("Segoe UI", 8), fg="#aaa").pack(side="left", padx=(14, 8))
        tk.Label(filter_bar, text="Legenda:", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 4))
        for _color, _desc in [
            ("#1565c0", "IP karty sieciowej"),
            ("#2e7d32", "Ta sama podsieć  "),
            ("#f57f17", "Inna podsieć  "),
            ("#c62828", "Konflikt IP"),
        ]:
            tk.Label(filter_bar, text="●", font=("Segoe UI", 11, "bold"), fg=_color).pack(side="left", padx=(0, 2))
            tk.Label(filter_bar, text=_desc, font=("Segoe UI", 8), fg="#444").pack(side="left", padx=(0, 8))

        # Columns: gear first, status second, then data columns.
        # Total widths fit in ~967px available (1020px window − padding − scrollbar).
        # Priority: gear, status, ip, producer, module_name, protocol — others shrink if needed.
        cols = ("config", "status", "ip", "mac", "producer", "module_name", "device_desc", "protocol", "vendor_id", "device_id", "version", "adapter")

        def _dot(color):
            img = tk.PhotoImage(width=12, height=12)
            img.put(color, to=(2, 1, 10, 11))
            img.put(color, to=(1, 2, 11, 10))
            return img

        self._ip_dot_images = {
            "local_adapter_ip": _dot("#1565c0"),
            "same_subnet": _dot("#2e7d32"),
            "diff_subnet": _dot("#f57f17"),
            "duplicate_ip": _dot("#c62828"),
        }

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)
        self.tree.heading("config",      text="")
        self.tree.heading("status",      text="")
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

        # action/status fixed; priority cols non-shrinkable; secondary cols shrink when window narrows.
        self.tree.column("config",      width=42,  minwidth=42,  stretch=False, anchor="center")
        self.tree.column("status",      width=18,  minwidth=18,  stretch=False, anchor="center")
        self.tree.column("ip",          width=100, minwidth=100, stretch=False)
        self.tree.column("mac",         width=112, minwidth=60)
        self.tree.column("producer",    width=112, minwidth=90,  stretch=False)
        self.tree.column("module_name", width=140, minwidth=90,  stretch=False)
        self.tree.column("device_desc", width=78,  minwidth=40)
        self.tree.column("protocol",    width=90,  minwidth=90,  stretch=False)
        self.tree.column("vendor_id",   width=60,  minwidth=40)
        self.tree.column("device_id",   width=65,  minwidth=40)
        self.tree.column("version",     width=55,  minwidth=40)
        self.tree.column("adapter",     width=105, minwidth=50)
        # sum of widths above = 947px — fits within ~967px available

        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<ButtonRelease-1>", self._on_tree_button_release, add="+")
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<Motion>", self._on_tree_motion)
        self.tree.bind("<Configure>", lambda _event: self._schedule_tree_overlay_refresh(), add="+")

        self._tree_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree_yview)
        self.tree.configure(yscrollcommand=self._on_tree_yscroll)
        self.tree.pack(side="left", fill="both", expand=True)
        self._tree_scrollbar.pack(side="right", fill="y")

        # Light flash to confirm click on action cell.
        self.tree.tag_configure("action_flash", background="#e3f2fd")
        self._tree_fixed_columns = {
            "config": 42,
            "status": 18,
        }

        # -- log --
        log_frame = tk.LabelFrame(main_pane, text="Log", padx=8, pady=4)
        main_pane.add(log_frame, minsize=120)

        self.log = scrolledtext.ScrolledText(log_frame, height=5,
                                              font=("Consolas", 8), state="disabled")
        self.log.pack(fill="both", expand=True)

        self.root.after_idle(lambda: main_pane.sash_place(0, 0, max(320, int(self.root.winfo_height() * 0.68))))

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

    def _on_adapter_selected(self, _event=None):
        self.clear_results()
        self.log_message(f"Wybrano adapter: {self.adapter_var.get()}")

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
            "",
            "",
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

    def _is_balluff_xg_ethercat(self, info: dict) -> bool:
        if (info.get("protocol") or "") != "EtherCAT":
            return False

        vid = -1
        try:
            vid = int(info.get("vendor_id_dec"))
        except Exception:
            vid_raw = str(info.get("vendor_id", "")).strip()
            try:
                vid = int(vid_raw, 16) if vid_raw.lower().startswith("0x") else int(vid_raw)
            except Exception:
                vid = -1

        # Official ETG Balluff ID is 0x010000E8; keep 0x00000378 for compatibility.
        if vid not in {0x010000E8, 0x00000378}:
            return False

        name = (
            info.get("product_name")
            or info.get("name")
            or info.get("device_name_sdo")
            or info.get("sii_name")
            or ""
        )
        return str(name).upper().startswith("BNI XG")

    def _is_visible(self, info):
        selected = self.vendor_filter_var.get() or self._all_vendors_label
        if selected == self._all_vendors_label:
            return True
        return self._producer_for_info(info) == selected

    def _rebuild_table(self):
        self._clear_tree_overlay_widgets()
        self._tree_row_device_map.clear()
        self._tree_row_ip_state_map.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        for info in self.found_devices:
            if self._is_visible(info):
                ip_state = self._get_ip_state(info)
                row_values = list(self._device_to_row(info))
                config_btn = ""
                if (info.get("protocol") or "") == "Profinet DCP":
                    config_btn = "SET"
                elif self._is_balluff_xg_ethercat(info):
                    config_btn = "SET"

                row_values[0] = config_btn
                row_values[1] = ""
                row_values[2] = self._format_ip_display(info.get("ip", ""), ip_state)
                row_id = self.tree.insert("", "end", values=tuple(row_values))
                self._tree_row_device_map[row_id] = info
                self._tree_row_ip_state_map[row_id] = ip_state
        self._enforce_fixed_tree_columns()
        self._schedule_tree_overlay_refresh()

    def _tree_yview(self, *args):
        self.tree.yview(*args)
        self._schedule_tree_overlay_refresh()

    def _on_tree_yscroll(self, first, last):
        self._tree_scrollbar.set(first, last)
        self._schedule_tree_overlay_refresh()

    def _schedule_tree_overlay_refresh(self):
        if self._tree_overlay_refresh_pending:
            return
        self._tree_overlay_refresh_pending = True
        self.root.after_idle(self._refresh_tree_overlay_widgets)

    def _clear_tree_overlay_widgets(self):
        for widget_pair in self._tree_overlay_widgets.values():
            for widget in widget_pair.values():
                widget.destroy()
        self._tree_overlay_widgets.clear()

    def _refresh_tree_overlay_widgets(self):
        self._tree_overlay_refresh_pending = False

        if not getattr(self, "tree", None):
            return

        style = ttk.Style()
        tree_bg = style.lookup("Treeview", "background") or style.lookup("Treeview", "fieldbackground") or "#ffffff"
        live_rows = set(self.tree.get_children())

        for row_id in list(self._tree_overlay_widgets):
            if row_id not in live_rows:
                widget_pair = self._tree_overlay_widgets.pop(row_id)
                for widget in widget_pair.values():
                    widget.destroy()

        for row_id, ip_state in self._tree_row_ip_state_map.items():
            if not self.tree.exists(row_id):
                continue

            widget_pair = self._tree_overlay_widgets.setdefault(row_id, {})

            config_bbox = self.tree.bbox(row_id, column="config")
            config_widget = widget_pair.get("config")
            config_value = self.tree.set(row_id, "config")
            if config_bbox and config_value == "SET":
                if config_widget is None:
                    config_widget = tk.Button(
                        self.tree,
                        text="SET",
                        bd=0,
                        padx=4,
                        pady=0,
                        background="#1565c0",
                        foreground="white",
                        activebackground="#0d47a1",
                        activeforeground="white",
                        cursor="hand2",
                        font=("Segoe UI", 7, "bold"),
                        relief="flat",
                        command=lambda rid=row_id: self._invoke_tree_config_action(rid),
                    )
                    widget_pair["config"] = config_widget
                else:
                    config_widget.configure(text="SET")
                x, y, width, height = config_bbox
                config_widget.place(x=x + max((width - 28) // 2, 0), y=y + max((height - 18) // 2, 0), width=28, height=18)
            elif config_widget is not None:
                config_widget.place_forget()

            status_bbox = self.tree.bbox(row_id, column="status")
            status_widget = widget_pair.get("status")
            status_image = self._ip_dot_images.get(ip_state)
            if status_bbox and status_image is not None:
                if status_widget is None:
                    status_widget = tk.Label(self.tree, image=status_image, bd=0, padx=0, pady=0, background=tree_bg)
                    widget_pair["status"] = status_widget
                else:
                    status_widget.configure(image=status_image, background=tree_bg)
                x, y, width, height = status_bbox
                status_widget.place(x=x + max((width - 12) // 2, 0), y=y + max((height - 12) // 2, 0))
            elif status_widget is not None:
                status_widget.place_forget()

    def _enforce_fixed_tree_columns(self):
        for column_name, width in self._tree_fixed_columns.items():
            self.tree.column(column_name, width=width, minwidth=width, stretch=False)

    def _on_tree_button_release(self, _event=None):
        self._enforce_fixed_tree_columns()
        self._schedule_tree_overlay_refresh()

    def _invoke_tree_config_action(self, row_id):
        dev = self._tree_row_device_map.get(row_id)
        if dev is None:
            return
        self._flash_tree_row(row_id)
        if (dev.get("protocol") or "") == "Profinet DCP":
            self._open_profinet_config(dev)
        elif self._is_balluff_xg_ethercat(dev):
            self._open_ethercat_eip_dialog(dev)

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
            (a.get("name", ""), a.get("description", ""), tuple(sorted(a.get("ips", []))))
            for a in adapters
        )

    def _adapter_label(self, adapter):
        ips = ", ".join(adapter.get("ips", [])) or "brak IP"
        return f"{adapter.get('description', '')}  [{ips}]"

    def _get_selected_adapter_index(self):
        selected_value = self.adapter_var.get().strip()
        if not selected_value or selected_value == "Wszystkie adaptery":
            return -1

        # Fast exact match first.
        for index, adapter in enumerate(self.adapters):
            if self._adapter_label(adapter) == selected_value:
                return index

        # Stable fallback by adapter description/name in case IP order in label changed.
        selected_head = selected_value.split("  [", 1)[0].strip().lower()
        for index, adapter in enumerate(self.adapters):
            desc = (adapter.get("description") or "").strip().lower()
            name = (adapter.get("name") or "").strip().lower()
            if selected_head and (selected_head == desc or selected_head == name):
                return index
        return -1

    def _refresh_adapters(self, force_log=False):
        current_value = self.adapter_var.get()
        current_index = self._get_selected_adapter_index()
        selected_name = ""
        if 0 <= current_index < len(self.adapters):
            selected_name = (self.adapters[current_index].get("name") or "").strip()

        new_adapters = get_adapters()
        new_sig = self._adapter_sig(new_adapters)
        if not force_log and new_sig == self._adapter_signature:
            return

        self.adapters = new_adapters
        self._adapter_signature = new_sig
        self._refresh_adapter_networks()

        names = ["Wszystkie adaptery"] + [self._adapter_label(a) for a in self.adapters]
        self.adapter_cb["values"] = names

        # Prefer restoring by stable adapter name, not full label text.
        restored = False
        if selected_name:
            for idx, adapter in enumerate(self.adapters):
                if (adapter.get("name") or "").strip() == selected_name:
                    self.adapter_cb.current(idx + 1)
                    restored = True
                    break

        if not restored and current_value in names:
            self.adapter_cb.current(names.index(current_value))
        else:
            if not restored:
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

    def _refresh_adapter_networks(self):
        """Build a fast MAC->IPv4 networks cache from ipconfig once per adapter refresh."""
        self._adapter_networks_by_mac = {}

        mac_re = re.compile(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})")
        ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

        output = ""
        ipconfig_candidates = [
            ["ipconfig", "/all"],
            [os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ipconfig.exe"), "/all"],
        ]
        for cmd in ipconfig_candidates:
            try:
                output = subprocess.check_output(
                    cmd,
                    text=True,
                    encoding="cp1252",
                    errors="replace",
                    timeout=8,
                )
                if output:
                    break
            except Exception as e:
                LOGGER.debug("ipconfig call failed for %s: %s", cmd[0], e)

        if not output:
            LOGGER.debug("Subnet cache: no ipconfig output available, using adapter fallback only")

        current_mac = ""
        current_ip = ""

        if output:
            for raw_line in output.splitlines():
                line = raw_line.strip()
                if not line:
                    continue

                low = line.lower()

                if "physical address" in low or "mac address" in low or "adres fizyczny" in low:
                    m = mac_re.search(line)
                    current_mac = m.group(1).lower().replace("-", ":") if m else ""
                    current_ip = ""
                    continue

                if (
                    "ipv4 address" in low
                    or "autoconfiguration ipv4 address" in low
                    or "adres ipv4" in low
                ):
                    if current_mac:
                        m = ip_re.search(line)
                        current_ip = m.group(1) if m else ""
                    continue

                if "subnet mask" in low or "maska podsieci" in low:
                    if current_mac and current_ip:
                        m = ip_re.search(line)
                        if m:
                            mask_str = m.group(1)
                            try:
                                net = ipaddress.ip_network(f"{current_ip}/{mask_str}", strict=False)
                                self._adapter_networks_by_mac.setdefault(current_mac, []).append(net)
                            except ValueError:
                                pass
                    current_ip = ""

        # Fallback for frozen/runtime edge-cases: infer local segment networks from adapter IPv4s.
        for adapter in self.adapters:
            mac = (adapter.get("mac") or "").strip().lower().replace("-", ":")
            if not mac:
                continue
            if self._adapter_networks_by_mac.get(mac):
                continue

            for ip_raw in adapter.get("ips", []):
                ip_s = (ip_raw or "").strip()
                if ":" in ip_s or not ip_s:
                    continue
                try:
                    ip_obj = ipaddress.ip_address(ip_s)
                except ValueError:
                    continue

                if ip_s.startswith("169.254."):
                    prefix = 16
                else:
                    # Conservative fallback used only when netmask is unavailable.
                    prefix = 24

                try:
                    net = ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False)
                    self._adapter_networks_by_mac.setdefault(mac, []).append(net)
                except ValueError:
                    continue

        LOGGER.debug("Subnet cache built for %d adapter MAC(s)", len(self._adapter_networks_by_mac))

    def _resolve_adapter_mac(self, adapter_name: str) -> str:
        """Resolve adapter MAC from adapter name/description reported by scanners."""
        needle = (adapter_name or "").strip().lower()
        if not needle:
            return ""

        for adapter in self.adapters:
            name = (adapter.get("name") or "").strip().lower()
            desc = (adapter.get("description") or "").strip().lower()
            mac = (adapter.get("mac") or "").strip().lower().replace("-", ":")
            if not mac:
                continue

            if needle == name or needle == desc:
                return mac
            if needle.endswith(name) or needle.endswith(desc):
                return mac
            if name and name in needle:
                return mac

        return ""

    def _is_ip_in_adapter_subnet(self, adapter_name: str, device_ip: str) -> bool:
        """Check if device_ip is in the same subnet as any IP assigned to adapter_name."""
        if not device_ip or device_ip in ("0.0.0.0", "255.255.255.255"):
            return False
        
        try:
            dev_addr = ipaddress.ip_address(device_ip)
        except ValueError:
            return False

        candidate_macs = []

        # Primary reference: currently selected adapter ("moja karta sieciowa").
        selected_index = self._get_selected_adapter_index()
        if 0 <= selected_index < len(self.adapters):
            mac_str = (self.adapters[selected_index].get("mac") or "").lower()
            selected_mac = mac_str.replace("-", ":")
            if selected_mac:
                candidate_macs.append(selected_mac)

        # Fallback/additional reference from packet-reported adapter.
        adapter_mac = self._resolve_adapter_mac(adapter_name)
        if adapter_mac and adapter_mac not in candidate_macs:
            candidate_macs.append(adapter_mac)

        if not candidate_macs:
            return False

        for mac in candidate_macs:
            for network in self._adapter_networks_by_mac.get(mac, []):
                try:
                    if dev_addr in network:
                        return True
                except Exception:
                    continue
        
        return False

    def _is_local_adapter_ip(self, adapter_name: str, device_ip: str) -> bool:
        if not device_ip or device_ip == "0.0.0.0":
            return False

        selected_index = self._get_selected_adapter_index()
        selected_adapter = None
        if 0 <= selected_index < len(self.adapters):
            selected_adapter = self.adapters[selected_index]
        else:
            adapter_name_l = str(adapter_name or "").strip().lower()
            for adapter in self.adapters:
                name_l = str(adapter.get("name") or "").strip().lower()
                desc_l = str(adapter.get("description") or "").strip().lower()
                if adapter_name_l and (adapter_name_l == name_l or adapter_name_l == desc_l):
                    selected_adapter = adapter
                    break

        if selected_adapter is None:
            return False

        ips = [str(ip).strip() for ip in selected_adapter.get("ips", []) if str(ip).strip()]
        return device_ip in ips

    def _get_ip_state(self, info: dict) -> str:
        """Return IP status key for display marker and click behaviors."""
        adapter = info.get("adapter", "?")
        ip = info.get("ip", "")

        if self._is_local_adapter_ip(adapter, ip):
            return "local_adapter_ip"

        if self._is_ip_conflict(adapter, ip):
            return "duplicate_ip"

        if ip and ip != "0.0.0.0":
            if self._is_ip_in_adapter_subnet(adapter, ip):
                return "same_subnet"
            return "diff_subnet"

        return "none"

    def _format_ip_display(self, ip: str, ip_state: str) -> str:
        # IP color is now represented by row text color (via tag)
        return ip.strip()

    def _strip_ip_marker(self, value: str) -> str:
        text = str(value or "").strip()
        text = re.sub(r"^[^0-9]*", "", text)
        return text

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
                # If conflict detected on this IP, unmerge any previously merged Profinet+ARP
                unmerged = self._unmerge_arp_profinet_by_ip(ip, adapter)
                macs = sorted(self._arp_ip_mac.get((adapter, ip), set()))
                key = (adapter, ip)
                if key not in self._arp_conflict_logged:
                    self._arp_conflict_logged.add(key)
                    msg = f"[UWAGA] Konflikt IP w ARP ({adapter}): {ip} — wiele MAC: {', '.join(macs)}"
                    if unmerged:
                        msg += " (rozpłączono scalony wpis)"
                    self.log_message(msg)
                if unmerged:
                    self._rebuild_table()
        elif changed:
            self._refresh_vendor_filter_options()
            self._rebuild_table()

        # After adding/updating ARP, try to merge with Profinet entries (same IP, no conflict)
        if ip:
            merged = self._merge_arp_profinet_by_ip(ip, info.get("adapter", "?"))
            if merged:
                self._rebuild_table()

        # Re-probe while scanning (with cooldown) so protocol switches are picked up without restart.
        self._schedule_identity_probes({"ip": dev.get("ip", ""), "adapter": dev.get("adapter", "?")})

    def _unmerge_arp_profinet_by_ip(self, ip: str, adapter: str):
        """When IP conflict detected, split merged Profinet+ARP back into separate entries."""
        if not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return False
        
        profinet_dev = None
        for dev in self.found_devices:
            dev_ip = (dev.get("ip") or "").strip()
            if dev_ip == ip and dev.get("protocol") == "Profinet DCP":
                profinet_dev = dev
                break
        
        if not profinet_dev:
            return False  # No Profinet device to unmerge
        
        profinet_mac = (profinet_dev.get("mac") or "").lower().strip()
        if not profinet_mac:
            return False
        
        # Check how many MACs are registered for this IP+adapter combo
        key = (adapter.strip(), ip.strip())
        macs = self._arp_ip_mac.get(key, set())
        if len(macs) <= 1:
            return False  # Not actually a conflict
        
        # Find another MAC (not the Profinet one) to create separate ARP entry
        other_macs = [m for m in macs if m.lower() != profinet_mac]
        if not other_macs:
            return False  # All MACs are the same, nothing to unmerge
        
        # Create a new ARP entry for first other MAC
        other_mac = other_macs[0]
        new_arp = {
            "ip": ip,
            "mac": other_mac,
            "protocol": "ARP",
            "adapter": adapter,
        }
        self.found_devices.append(new_arp)
        return True

    def _merge_arp_profinet_by_ip(self, ip: str, adapter: str):
        """Find ARP + Profinet with same IP (no IP conflict) and merge them. Returns True if merged."""
        if not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return False
        
        # Check if this IP is in conflict (multiple MACs on same adapter+IP)
        key = (adapter.strip(), ip.strip())
        if key in self._arp_ip_mac and len(self._arp_ip_mac[key]) > 1:
            return False  # IP conflict, don't merge
        
        profinet = None
        arp = None
        
        for dev in self.found_devices:
            dev_ip = (dev.get("ip") or "").strip()
            if dev_ip != ip:
                continue
            if dev.get("protocol") == "Profinet DCP":
                profinet = dev
            elif dev.get("protocol") == "ARP":
                arp = dev
        
        if profinet and arp:
            # Merge: copy Profinet data into ARP, then remove the Profinet entry
            arp["protocol"] = "Profinet DCP"
            for key in ("name_of_station", "type_of_station", "vendor_id", "device_id", 
                       "device_role", "device_instance", "firmware", "vendor_name", "mac"):
                if key in profinet and not arp.get(key):
                    arp[key] = profinet[key]
            # Remove duplicate Profinet entry
            if profinet in self.found_devices:
                self.found_devices.remove(profinet)
            return True
        return False

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
            self._rebuild_table()
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
        self._clear_tree_overlay_widgets()
        self._tree_row_device_map.clear()
        self._tree_row_ip_state_map.clear()
        with self._probe_lock:
            self._scheduled_protocol_probes.clear()
        self._arp_ip_mac.clear()
        self._arp_conflict_logged.clear()
        self._refresh_vendor_filter_options()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.log_message("Wyniki wyczyszczone.")

    # ── Tree click handler ────────────────────────────────────────────────────

    def _on_tree_click(self, event):
        """Handle clicks on first action column for supported devices."""
        region = self.tree.identify_region(event.x, event.y)
        if region == "separator" and event.x <= (self._tree_fixed_columns["config"] + self._tree_fixed_columns["status"] + 8):
            return "break"
        if region != "cell":
            return
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        if self.tree.identify_column(event.x) != "#1":
            return
        if self.tree.set(row_id, "config") != "SET":
            return
        self._invoke_tree_config_action(row_id)
        return "break"

    def _on_tree_motion(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region != "cell":
            self.tree.configure(cursor="")
            return
        col_id = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            self.tree.configure(cursor="")
            return
        if col_id == "#1" and self.tree.set(row_id, "config") == "SET":
            self.tree.configure(cursor="hand2")
        else:
            self.tree.configure(cursor="")

    def _on_tree_double_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region != "cell":
            return
        col_id = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return

        col_index = int(col_id.lstrip("#")) - 1
        col_names = self.tree["columns"]
        if col_index < 0 or col_index >= len(col_names):
            return
        if col_names[col_index] != "ip":
            return

        ip_state = self._tree_row_ip_state_map.get(row_id)
        if ip_state != "same_subnet":
            return

        ip_raw = self._strip_ip_marker(self.tree.set(row_id, "ip"))
        if not ip_raw or ip_raw == "0.0.0.0":
            return
        webbrowser.open(f"http://{ip_raw}")
        self.log_message(f"Otwieram panel urządzenia: http://{ip_raw}")

    def _flash_tree_row(self, row_id: str):
        prev_tags = self.tree.item(row_id, "tags")
        self.tree.item(row_id, tags=("action_flash",))

        def _restore():
            if self.tree.exists(row_id):
                self.tree.item(row_id, tags=prev_tags)

        self.root.after(130, _restore)

    def _open_ethercat_eip_dialog(self, dev: dict):
        """Dialog for switching Balluff BNI XG EtherCAT device to Ethernet/IP."""
        win = tk.Toplevel(self.root)
        win.title("EtherCAT -> Ethernet/IP")
        win.geometry("490x260")
        win.resizable(False, False)
        win.grab_set()

        panel = tk.LabelFrame(win, text="Przełączenie interfejsu", padx=10, pady=8)
        panel.pack(fill="both", expand=True, padx=10, pady=10)

        module_name = dev.get("product_name") or dev.get("name") or "?"
        rows = [
            ("Moduł:", module_name),
            ("Vendor ID:", dev.get("vendor_id", "?")),
            ("Slave index:", str(dev.get("slave_index", "?"))),
            ("Adapter:", dev.get("adapter", "?")),
        ]
        for i, (k, v) in enumerate(rows):
            tk.Label(panel, text=k, font=("Segoe UI", 8, "bold"), anchor="w").grid(row=i, column=0, sticky="w", padx=(0, 8))
            tk.Label(panel, text=v, font=("Segoe UI", 8), anchor="w").grid(row=i, column=1, sticky="w")

        tk.Label(
            panel,
            text="Akcja wyśle sekwencję CoE SDO (set + reboot): 0xF502:02, 0xF503:01, 0xF503:02.",
            font=("Segoe UI", 8),
            fg="#555",
            wraplength=455,
            justify="left",
            anchor="w",
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

        status_var = tk.StringVar(value="")
        status_lbl = tk.Label(panel, textvariable=status_var, font=("Segoe UI", 8), wraplength=455, anchor="w")
        status_lbl.grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))

        def _switch():
            btn_switch.config(state="disabled")
            status_var.set("Wysyłanie sekwencji…")
            status_lbl.config(fg="#444")

            if self.scanning:
                self._stop_scan()
                self.log_message("[EtherCAT] Zatrzymano skan przed przełączeniem interfejsu.")

            adapter = dev.get("adapter", "")
            slave_index = int(dev.get("slave_index", -1))
            expected_vendor_id = dev.get("vendor_id_dec")
            expected_product_code = dev.get("product_code_dec")
            expected_serial = dev.get("serial_dec")

            def run():
                ok, msg = switch_balluff_xg_to_eip(
                    adapter,
                    slave_index,
                    expected_vendor_id=expected_vendor_id,
                    expected_product_code=expected_product_code,
                    expected_serial=expected_serial,
                )

                def finish():
                    if ok:
                        status_var.set(f"✓ {msg}. Zrób ponowny skan, aby sprawdzić efekt.")
                        status_lbl.config(fg="#2e7d32")
                        self.log_message(
                            f"[EtherCAT] Wysłano przełączenie do EIP: {module_name} (slave {slave_index})"
                        )
                    else:
                        status_var.set(f"✗ {msg}")
                        status_lbl.config(fg="#c62828")
                        self.log_message(
                            f"[EtherCAT] Błąd przełączenia do EIP: {module_name} (slave {slave_index}) -> {msg}"
                        )
                    btn_switch.config(state="normal")

                self.root.after(0, finish)

            threading.Thread(target=run, daemon=True).start()

        btn_bar = tk.Frame(win)
        btn_bar.pack(fill="x", padx=10, pady=(0, 8))
        btn_switch = tk.Button(
            btn_bar,
            text="Przełącz na EIP",
            command=_switch,
            bg="#1565c0",
            fg="white",
            font=("Segoe UI", 8, "bold"),
        )
        btn_switch.pack(side="left")
        tk.Button(btn_bar, text="Zamknij", command=win.destroy, font=("Segoe UI", 8)).pack(side="right")

    # ── Profinet config dialog ────────────────────────────────────────────────

    def _open_profinet_config(self, dev: dict):
        """Open the Profinet DCP configuration dialog for the given device."""
        win = tk.Toplevel(self.root)
        win.title("Konfiguracja Profinet DCP")
        win.geometry("560x520")
        win.minsize(520, 500)
        win.resizable(True, True)
        win.grab_set()

        content = tk.Frame(win)
        content.pack(fill="both", expand=True, padx=10, pady=(10, 4))

        # ── Device info header ────────────────────────────────────────────
        header = tk.LabelFrame(content, text="Urządzenie", padx=8, pady=6)
        header.pack(fill="x", pady=(0, 4))
        header.columnconfigure(1, weight=1)

        header_fields = [
            ("Adres MAC:", "mac"),
            ("Aktualny IP:", "ip"),
            ("Nazwa stacji:", "name_of_station"),
            ("Adapter:", "adapter"),
        ]
        header_vars = {
            key: tk.StringVar(value=(dev.get(key, "") or "—"))
            for _label, key in header_fields
        }

        def _refresh_dialog_device_state(latest_info=None):
            if latest_info:
                for key in ("mac", "ip", "name_of_station", "adapter"):
                    value = latest_info.get(key)
                    if value:
                        dev[key] = value.strip() if isinstance(value, str) else value

            for _label, key in header_fields:
                value = dev.get(key, "")
                if key == "name_of_station" and value:
                    value = str(value).lower()
                    dev[key] = value
                header_vars[key].set(value or "—")

        for row_idx, (label, key) in enumerate(header_fields):
            tk.Label(header, text=label, anchor="w", font=("Segoe UI", 8, "bold")
                     ).grid(row=row_idx, column=0, sticky="w", padx=(0, 6))
            tk.Label(header, textvariable=header_vars[key], anchor="w", font=("Segoe UI", 8)
                     ).grid(row=row_idx, column=1, sticky="ew")

        # ── IP settings ───────────────────────────────────────────────────
        ip_frame = tk.LabelFrame(content, text="Zmień adres IP", padx=8, pady=6)
        ip_frame.pack(fill="x", pady=4)
        ip_frame.columnconfigure(1, weight=1)

        tk.Label(ip_frame, text="Nowy adres IP:", font=("Segoe UI", 8)).grid(row=0, column=0, sticky="w")
        ip_var = tk.StringVar(value=dev.get("ip", ""))
        tk.Entry(ip_frame, textvariable=ip_var, width=18, font=("Segoe UI", 8)
                 ).grid(row=0, column=1, padx=6, sticky="ew")

        tk.Label(ip_frame, text="Maska podsieci:", font=("Segoe UI", 8)).grid(row=1, column=0, sticky="w", pady=2)
        mask_var = tk.StringVar(value="255.255.255.0")
        tk.Entry(ip_frame, textvariable=mask_var, width=18, font=("Segoe UI", 8)
                 ).grid(row=1, column=1, padx=6, sticky="ew")

        tk.Label(ip_frame, text="Brama domyślna:", font=("Segoe UI", 8)).grid(row=2, column=0, sticky="w")
        gw_var = tk.StringVar(value="0.0.0.0")
        tk.Entry(ip_frame, textvariable=gw_var, width=18, font=("Segoe UI", 8)
                 ).grid(row=2, column=1, padx=6, sticky="ew")

        ip_permanent_var = tk.BooleanVar(value=True)
        tk.Checkbutton(ip_frame, text="Zapisz trwale (permanent)", variable=ip_permanent_var,
                       font=("Segoe UI", 8)).grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))

        ip_status_var = tk.StringVar(value="")
        ip_status_lbl = tk.Label(ip_frame, textvariable=ip_status_var, font=("Segoe UI", 8),
                                  anchor="w", justify="left", wraplength=500)
        ip_status_lbl.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(2, 0))

        def _verify_persistence_async(field_name: str, expected_value: str, set_msg: str, status_var, status_lbl):
            """Verify after SET whether value stayed on device or got overwritten by controller."""

            adapter_name = dev.get("adapter", "")
            target_mac = dev.get("mac", "")

            def run_verify():
                # Give PLC/controller a moment to potentially overwrite parameters.
                time.sleep(1.6)
                info = identify_dcp_device(adapter_name, target_mac, timeout=3.0)

                def finish_verify():
                    if not status_lbl.winfo_exists():
                        return
                    if not info:
                        status_var.set("⚠ Nie udało się zweryfikować (brak odpowiedzi Identify).")
                        status_lbl.config(fg="#e65100")
                        return

                    actual_ip = (info.get("ip") or "").strip()
                    actual_name = (info.get("name_of_station") or "").strip().lower()

                    # Refresh local row data and dialog header from latest Identify response.
                    _refresh_dialog_device_state(info)
                    if actual_ip:
                        ip_var.set(actual_ip)
                    if actual_name:
                        name_var.set(actual_name)
                    self._rebuild_table()

                    if field_name == "ip":
                        expected = expected_value.strip()
                        if actual_ip == expected:
                            status_var.set(f"✓ IP zmieniony na {actual_ip}")
                            status_lbl.config(fg="#2e7d32")
                            # Merge ARP with Profinet if they share the same new IP (no conflict)
                            self._merge_arp_profinet_by_ip(actual_ip, adapter_name)
                            self._rebuild_table()
                        else:
                            if set_msg.startswith("OK"):
                                status_var.set(
                                    f"⚠ Weryfikacja: po chwili IP={actual_ip or '?'} (oczekiwano {expected}). "
                                    "Zmiana nieutrzymana (możliwe nadpisanie przez controller lub logikę urządzenia)."
                                )
                            else:
                                status_var.set(
                                    f"⚠ Weryfikacja: IP pozostał {actual_ip or '?'} (oczekiwano {expected}). "
                                    "SET nie został skutecznie potwierdzony przez urządzenie."
                                )
                            status_lbl.config(fg="#c62828")
                            self.log_message(
                                f"[Profinet] Weryfikacja: IP urządzenia {target_mac} niezgodny "
                                f"({expected} -> {actual_ip or '?'}, set_msg={set_msg})"
                            )
                    elif field_name == "name":
                        expected = expected_value.strip().lower()
                        if actual_name == expected:
                            status_var.set(f"✓ Nazwa zmieniona na '{actual_name}'")
                            status_lbl.config(fg="#2e7d32")
                        else:
                            if set_msg.startswith("OK"):
                                status_var.set(
                                    f"⚠ Weryfikacja: po chwili nazwa='{actual_name or ''}' "
                                    f"(oczekiwano '{expected}'). Zmiana nieutrzymana."
                                )
                            else:
                                status_var.set(
                                    f"⚠ Weryfikacja: nazwa pozostała '{actual_name or ''}' "
                                    f"(oczekiwano '{expected}'). SET nie został skutecznie potwierdzony."
                                )
                            status_lbl.config(fg="#c62828")
                            self.log_message(
                                f"[Profinet] Weryfikacja: nazwa stacji {target_mac} niezgodna "
                                f"('{expected}' -> '{actual_name or ''}', set_msg={set_msg})"
                            )

                self.root.after(0, finish_verify)

            threading.Thread(target=run_verify, daemon=True).start()

        def _set_ip():
            btn_ip.config(state="disabled")
            ip_status_var.set("Wysyłanie…")
            win.update_idletasks()

            def do():
                ok, msg = send_dcp_set_ip(
                    adapter_name=dev.get("adapter", ""),
                    target_mac=dev.get("mac", ""),
                    new_ip=ip_var.get().strip(),
                    new_mask=mask_var.get().strip(),
                    new_gateway=gw_var.get().strip(),
                    permanent=ip_permanent_var.get(),
                )
                def finish():
                    if ok:
                        dev["ip"] = ip_var.get().strip()
                        _refresh_dialog_device_state()
                        ip_status_var.set(f"✓ Zmiana wysłana ({msg})")
                        ip_status_lbl.config(fg="#2e7d32")
                        self._rebuild_table()
                        _verify_persistence_async("ip", ip_var.get().strip(), msg, ip_status_var, ip_status_lbl)
                        self.log_message(
                            f"[Profinet] IP urządzenia {dev.get('mac','')} → {ip_var.get().strip()} ({msg})"
                        )
                    else:
                        ip_status_var.set(f"✗ {msg}")
                        ip_status_lbl.config(fg="#c62828")
                    btn_ip.config(state="normal")
                win.after(0, finish)

            threading.Thread(target=do, daemon=True).start()

        btn_ip = tk.Button(ip_frame, text="Ustaw IP", font=("Segoe UI", 8, "bold"),
                            bg="#1565c0", fg="white", command=_set_ip)
        btn_ip.grid(row=5, column=0, columnspan=2, pady=(6, 2))

        # ── Name settings ─────────────────────────────────────────────────
        name_frame = tk.LabelFrame(content, text="Zmień nazwę stacji Profinet", padx=8, pady=6)
        name_frame.pack(fill="x", pady=4)
        name_frame.columnconfigure(1, weight=1)

        tk.Label(name_frame, text="Nowa nazwa:", font=("Segoe UI", 8)).grid(row=0, column=0, sticky="w")
        name_var = tk.StringVar(value=dev.get("name_of_station", ""))
        tk.Entry(name_frame, textvariable=name_var, width=30, font=("Segoe UI", 8)
             ).grid(row=0, column=1, padx=6, sticky="ew")

        tk.Label(name_frame, text="(a–z, 0–9, myślnik, kropka; maks. 240 znaków)",
                 font=("Segoe UI", 7), fg="#666").grid(row=1, column=0, columnspan=2, sticky="w")

        name_permanent_var = tk.BooleanVar(value=True)
        tk.Checkbutton(name_frame, text="Zapisz trwale (permanent)", variable=name_permanent_var,
                       font=("Segoe UI", 8)).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        name_status_var = tk.StringVar(value="")
        name_status_lbl = tk.Label(name_frame, textvariable=name_status_var, font=("Segoe UI", 8),
                                    anchor="w", justify="left", wraplength=500)
        name_status_lbl.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 0))

        def _set_name():
            btn_name.config(state="disabled")
            name_status_var.set("Wysyłanie…")
            win.update_idletasks()

            def do():
                ok, msg = send_dcp_set_name(
                    adapter_name=dev.get("adapter", ""),
                    target_mac=dev.get("mac", ""),
                    new_name=name_var.get().strip(),
                    permanent=name_permanent_var.get(),
                )
                def finish():
                    if ok:
                        dev["name_of_station"] = name_var.get().strip().lower()
                        _refresh_dialog_device_state()
                        name_status_var.set(f"✓ Zmiana wysłana ({msg})")
                        name_status_lbl.config(fg="#2e7d32")
                        self._rebuild_table()
                        _verify_persistence_async("name", name_var.get().strip(), msg, name_status_var, name_status_lbl)
                        self.log_message(
                            f"[Profinet] Nazwa stacji {dev.get('mac','')} → '{name_var.get().strip()}' ({msg})"
                        )
                    else:
                        name_status_var.set(f"✗ {msg}")
                        name_status_lbl.config(fg="#c62828")
                    btn_name.config(state="normal")
                win.after(0, finish)

            threading.Thread(target=do, daemon=True).start()

        btn_name = tk.Button(name_frame, text="Ustaw nazwę", font=("Segoe UI", 8, "bold"),
                              bg="#1565c0", fg="white", command=_set_name)
        btn_name.grid(row=4, column=0, columnspan=2, pady=(6, 2))

        btn_bar = tk.Frame(win)
        btn_bar.pack(fill="x", padx=10, pady=(0, 8))
        tk.Button(btn_bar, text="Zamknij", command=win.destroy,
              font=("Segoe UI", 8)).pack(side="right")