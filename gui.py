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

REPO_URL = "https://github.com/marjac6/balluff-scanner"


def _resource_path(filename):
    """Resolve path to bundled resource — works for both script and frozen EXE."""
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
        self.root.geometry("860x620")
        self.root.resizable(True, True)
        self.root.minsize(640, 480)
        self.stop_event    = threading.Event()
        self.scanning      = False
        self.found_devices = []

        # Load GitHub logo from SVG; fall back to None if file missing or broken
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
        self._load_adapters()

    def _build_ui(self):
        # -- adapter selector --
        top = tk.LabelFrame(self.root, text="Adapter sieciowy", padx=8, pady=6)
        top.pack(fill="x", padx=10, pady=(10, 4))

        tk.Label(top, text="Skanuj:").grid(row=0, column=0, sticky="w")

        self.adapter_var = tk.StringVar(value="Wszystkie adaptery")
        self.adapter_cb  = ttk.Combobox(top, textvariable=self.adapter_var, width=55, state="readonly")
        self.adapter_cb.grid(row=0, column=1, padx=8)

        self.btn_scan = tk.Button(
            top, text="▶  Start", width=12,
            bg="#2e7d32", fg="white", font=("Segoe UI", 9, "bold"),
            command=self.toggle_scan
        )
        self.btn_scan.grid(row=0, column=2, padx=4)

        self.btn_clear = tk.Button(top, text="🗑  Wyczyść", width=12, command=self.clear_results)
        self.btn_clear.grid(row=0, column=3, padx=4)

        # -- status bar --
        self.status_var = tk.StringVar(value="Gotowy")
        tk.Label(
            self.root, textvariable=self.status_var,
            anchor="w", relief="sunken", font=("Segoe UI", 8)
        ).pack(fill="x", padx=10, pady=(0, 4))

        # -- results table --
        table_frame = tk.LabelFrame(self.root, text="Znalezione urządzenia", padx=8, pady=6)
        table_frame.pack(fill="both", expand=True, padx=10, pady=4)

        cols = ("ip", "mac", "name", "protocol", "vendor_id", "device_id", "adapter")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)
        self.tree.heading("ip",        text="Adres IP")
        self.tree.heading("mac",       text="Adres MAC")
        self.tree.heading("name",      text="Nazwa / Producent")
        self.tree.heading("protocol",  text="Protokół")
        self.tree.heading("vendor_id", text="VendorID")
        self.tree.heading("device_id", text="DeviceID")
        self.tree.heading("adapter",   text="Adapter")
        self.tree.column("ip",        width=120)
        self.tree.column("mac",       width=145)
        self.tree.column("name",      width=160)
        self.tree.column("protocol",  width=100)
        self.tree.column("vendor_id", width=70)
        self.tree.column("device_id", width=70)
        self.tree.column("adapter",   width=170)

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # -- log --
        log_frame = tk.LabelFrame(self.root, text="Log", padx=8, pady=4)
        log_frame.pack(fill="x", padx=10, pady=(4, 2))

        self.log = scrolledtext.ScrolledText(log_frame, height=5, font=("Consolas", 8), state="disabled")
        self.log.pack(fill="x")

        # -- bottom bar: version + repo link --
        bottom = tk.Frame(self.root, bg="#f0f0f0", bd=1, relief="sunken")
        bottom.pack(fill="x", padx=0, pady=(2, 0))

        tk.Label(
            bottom, text=f"v{__version__}",
            font=("Consolas", 7), fg="#888", bg="#f0f0f0"
        ).pack(side="left", padx=8)

        tk.Button(
            bottom, text="changelog",
            font=("Segoe UI", 7), fg="#555", bg="#f0f0f0",
            relief="flat", cursor="hand2",
            command=self._show_changelog
        ).pack(side="left", padx=2)

        repo_frame = tk.Frame(bottom, bg="#f0f0f0")
        repo_frame.pack(side="right", padx=8)

        if self.github_logo:
            tk.Label(repo_frame, image=self.github_logo, bg="#f0f0f0").pack(side="left")

        lnk = tk.Label(
            repo_frame, text="github: balluff-scanner",
            font=("Segoe UI", 7, "underline"), fg="#0969da", bg="#f0f0f0", cursor="hand2"
        )
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

    def _load_adapters(self):
        self.adapters = get_adapters()
        names = ["Wszystkie adaptery"] + [
            f"{a['description']}  [{', '.join(a['ips']) or 'brak IP'}]"
            for a in self.adapters
        ]
        self.adapter_cb["values"] = names
        self.adapter_cb.current(0)
        self.log_message(f"Found {len(self.adapters)} adapter(s).")

    def log_message(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def on_device_found(self, info):
        self.root.after(0, self._add_device, info)

    def on_profinet_found(self, info):
        self.root.after(0, self._add_profinet_device, info)

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
            "", "",
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
            info.get("adapter", "?"),
        ))
        self.log_message(
            f"🏭 Profinet: {info.get('name_of_station', '?')}  "
            f"IP={info.get('ip', '?')}  MAC={info.get('mac', '?')}"
        )

    def toggle_scan(self):
        if not self.scanning:
            self._start_scan()
        else:
            self._stop_scan()

    def _start_scan(self):
        self.scanning = True
        self.stop_event.clear()
        self.btn_scan.config(text="⏹  Stop", bg="#c62828")
        self.status_var.set("⏳ Skanowanie w toku…")

        selected = self.adapter_cb.current()

        if selected == 0:
            self.log_message("Starting ARP + Profinet DCP on all adapters…")
            threading.Thread(target=start_active_scan,  args=(self.on_device_found,   self.stop_event), daemon=True).start()
            threading.Thread(target=start_dcp_scan_all, args=(self.on_profinet_found, self.stop_event), daemon=True).start()
        else:
            adapter = self.adapters[selected - 1]
            self.log_message(f"Starting ARP + Profinet DCP on: {adapter['description']}…")
            threading.Thread(target=start_scan,     args=(adapter["name"], self.on_device_found,   self.stop_event), daemon=True).start()
            threading.Thread(target=send_arp_probe, args=(adapter["name"], self.stop_event),                         daemon=True).start()
            threading.Thread(target=start_dcp_scan, args=(adapter["name"], self.on_profinet_found, self.stop_event), daemon=True).start()

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
