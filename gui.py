# gui.py
import sys
import os
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import webbrowser
from svglib.svglib import svg2rlg
from reportlab.graphics import renderPM
from PIL import Image, ImageTk
from io import BytesIO
from version import __version__
from scanner import get_adapters, start_scan, start_active_scan, send_arp_probe
from profinet_scanner import start_dcp_scan_all, start_dcp_scan
from ethercat_scanner import start_ecat_scan_all, start_ecat_scan

REPO_URL = "https://github.com/marjac6/balluff-scanner"
ADAPTER_REFRESH_IDLE_MS = 5000
ADAPTER_REFRESH_SCANNING_MS = 15000


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
        self.root.title(f"Balluff / BNI Device Scanner  v{__version__}")
        self.root.geometry("1020x640")
        self.root.resizable(True, True)
        self.root.minsize(720, 480)
        self.stop_event    = threading.Event()
        self.scanning      = False
        self.found_devices = []
        self.adapters = []
        self._adapter_signature = ()

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
            top, text="▶  Start", width=12,
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

        cols = ("ip", "mac", "name", "protocol", "vendor_id", "device_id", "version", "adapter")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)

        self.tree.heading("ip",        text="Adres IP")
        self.tree.heading("mac",       text="Adres MAC")
        self.tree.heading("name",      text="Nazwa / Producent")
        self.tree.heading("protocol",  text="Protokół")
        self.tree.heading("vendor_id", text="VendorID")
        self.tree.heading("device_id", text="DeviceID / ProductName")
        self.tree.heading("version",   text="Version")
        self.tree.heading("adapter",   text="Adapter")

        self.tree.column("ip",        width=110)
        self.tree.column("mac",       width=140)
        self.tree.column("name",      width=185)
        self.tree.column("protocol",  width=105)
        self.tree.column("vendor_id", width=90)
        self.tree.column("device_id", width=175)
        self.tree.column("version",   width=65)
        self.tree.column("adapter",   width=155)

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

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

        tk.Button(bottom, text="changelog",
                  font=("Segoe UI", 7), fg="#555", bg="#f0f0f0",
                  relief="flat", cursor="hand2",
                  command=self._show_changelog).pack(side="left", padx=2)

        repo_frame = tk.Frame(bottom, bg="#f0f0f0")
        repo_frame.pack(side="right", padx=8)
        if self.github_logo:
            tk.Label(repo_frame, image=self.github_logo, bg="#f0f0f0").pack(side="left")
        lnk = tk.Label(repo_frame, text="github: balluff-scanner",
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

    def _adapter_sig(self, adapters):
        return tuple(
            (a.get("name", ""), a.get("description", ""), tuple(a.get("ips", [])))
            for a in adapters
        )

    def _adapter_label(self, adapter):
        ips = ", ".join(adapter.get("ips", [])) or "brak IP"
        return f"{adapter.get('description', '')}  [{ips}]"

    def _refresh_adapters(self, force_log=False):
        current_value = self.adapter_var.get()
        current_index = self.adapter_cb.current()
        new_adapters = get_adapters()
        new_sig = self._adapter_sig(new_adapters)
        if not force_log and new_sig == self._adapter_signature:
            return

        self.adapters = new_adapters
        self._adapter_signature = new_sig

        names = ["Wszystkie adaptery"] + [self._adapter_label(a) for a in self.adapters]
        self.adapter_cb["values"] = names

        if current_value in names:
            self.adapter_var.set(current_value)
        else:
            self.adapter_cb.current(0)
            if self.scanning and current_index > 0:
                self.log_message("Selected adapter disconnected/removed. Stopping scan.")
                self._stop_scan()

        self.log_message(f"Adapters updated: {len(self.adapters)} available.")

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

    # ── Device adders ─────────────────────────────────────────────────────────

    def _add_device(self, info):
        key = (info["ip"], info["mac"])
        if key in [(d.get("ip"), d.get("mac")) for d in self.found_devices]:
            return
        self.found_devices.append(info)
        self.tree.insert("", "end", values=(
            info.get("ip", ""),
            info.get("mac", ""),
            info.get("keyword", ""),
            info.get("type", "ARP"),
            "", "", "",
            info.get("adapter", "?"),
        ))
        self.log_message(
            f"✔ ARP: {info.get('keyword','?')}  IP={info.get('ip','?')}  "
            f"MAC={info.get('mac','?')}  [{info.get('adapter','?')}]"
        )

    def _add_profinet_device(self, info):
        key = (info.get("ip", ""), info.get("mac", ""))
        if key in [(d.get("ip"), d.get("mac")) for d in self.found_devices]:
            return
        self.found_devices.append(info)
        self.tree.insert("", "end", values=(
            info.get("ip", ""),
            info.get("mac", ""),
            info.get("name_of_station", ""),
            "Profinet DCP",
            info.get("vendor_id", ""),
            info.get("device_id", ""),
            "",
            info.get("adapter", "?"),
        ))
        self.log_message(
            f"🏭 Profinet: {info.get('name_of_station', '?')}  "
            f"IP={info.get('ip', '?')}  MAC={info.get('mac', '?')}"
        )

    def _add_ecat_device(self, info):
        """
        Deduplikacja EtherCAT po (adapter, vendor_id, product_name).
        Wyświetla:
          name       = product_name (np. "BNI XG5-538-0B5-R067")
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

        self.found_devices.append(info)
        self.tree.insert("", "end", values=(
            "",                                  # ip
            "N/A",                               # mac
            product_name or info.get("name",""), # name
            "EtherCAT",                          # protocol
            vendor_id,                           # vendor_id
            product_code,                        # device_id column = EtherCAT Product Code
            sw_version,                          # version column
            info.get("adapter", "?"),            # adapter
        ))
        self.log_message(
            f"⚡ EtherCAT: {product_name or '?'}  "
            f"v{sw_version}  VID={vendor_id}  PID={product_code}  "
            f"[{info.get('adapter','?')}]"
        )

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
        self.btn_scan.config(text="⏹  Stop", bg="#c62828")
        self.status_var.set("⏳ Skanowanie w toku…")

        selected = self.adapter_cb.current()

        if selected == 0:
            self.log_message("Starting ARP + Profinet DCP + EtherCAT on all adapters…")
            threading.Thread(
                target=start_active_scan,
                args=(self.on_device_found, self.stop_event), daemon=True).start()
            threading.Thread(
                target=start_dcp_scan_all,
                args=(self.on_profinet_found, self.stop_event), daemon=True).start()
            threading.Thread(
                target=start_ecat_scan_all,
                args=(self.on_ecat_found, self.stop_event), daemon=True).start()
        else:
            idx = selected - 1
            if idx < 0 or idx >= len(self.adapters):
                self.log_message("Selected adapter is no longer available. Refreshing list.")
                self._refresh_adapters(force_log=True)
                self._stop_scan()
                return

            adapter = self.adapters[idx]
            self.log_message(
                f"Starting ARP + Profinet DCP + EtherCAT on: {adapter['description']}…")
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
                target=start_ecat_scan,
                args=(adapter["name"], self.on_ecat_found, self.stop_event), daemon=True).start()

    def _stop_scan(self):
        self.scanning = False
        self.stop_event.set()
        self.btn_scan.config(text="▶  Start", bg="#2e7d32")
        self.status_var.set("Zatrzymano.")
        self.log_message("Scan stopped.")

    def clear_results(self):
        self.found_devices.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.log_message("Results cleared.")