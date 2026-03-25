# scanner.py
# Logika skanowania ramek ARP - Balluff/BNI detector

# gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scanner import get_adapters, start_scan_all, start_scan

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Balluff / BNI Device Scanner")
        self.root.geometry("750x520")
        self.root.resizable(True, True)

        self.stop_event = threading.Event()
        self.scanning = False
        self.found_devices = []

        self._build_ui()
        self._load_adapters()

    def _build_ui(self):
        # ── Górny panel: wybór adaptera ──────────────────────────
        top = tk.LabelFrame(self.root, text="Adapter sieciowy", padx=8, pady=6)
        top.pack(fill="x", padx=10, pady=(10, 4))

        tk.Label(top, text="Skanuj:").grid(row=0, column=0, sticky="w")

        self.adapter_var = tk.StringVar(value="Wszystkie adaptery")
        self.adapter_cb = ttk.Combobox(top, textvariable=self.adapter_var, width=55, state="readonly")
        self.adapter_cb.grid(row=0, column=1, padx=8)

        self.btn_scan = tk.Button(top, text="▶  Start", width=12,
                                   bg="#2e7d32", fg="white", font=("Segoe UI", 9, "bold"),
                                   command=self.toggle_scan)
        self.btn_scan.grid(row=0, column=2, padx=4)

        self.btn_clear = tk.Button(top, text="🗑  Wyczyść", width=12,
                                    command=self.clear_results)
        self.btn_clear.grid(row=0, column=3, padx=4)

        # ── Status ───────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Gotowy")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                               anchor="w", relief="sunken", font=("Segoe UI", 8))
        status_bar.pack(fill="x", padx=10, pady=(0, 4))

        # ── Tabela wyników ───────────────────────────────────────
        table_frame = tk.LabelFrame(self.root, text="Znalezione urządzenia", padx=8, pady=6)
        table_frame.pack(fill="both", expand=True, padx=10, pady=4)

        cols = ("ip", "mac", "keyword", "adapter")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)
        self.tree.heading("ip",      text="Adres IP")
        self.tree.heading("mac",     text="Adres MAC")
        self.tree.heading("keyword", text="Słowo kluczowe")
        self.tree.heading("adapter", text="Adapter")

        self.tree.column("ip",      width=140)
        self.tree.column("mac",     width=160)
        self.tree.column("keyword", width=120)
        self.tree.column("adapter", width=280)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # ── Log ──────────────────────────────────────────────────
        log_frame = tk.LabelFrame(self.root, text="Log", padx=8, pady=4)
        log_frame.pack(fill="x", padx=10, pady=(4, 10))

        self.log = scrolledtext.ScrolledText(log_frame, height=6,
                                              font=("Consolas", 8), state="disabled")
        self.log.pack(fill="x")

    def _load_adapters(self):
        adapters = get_adapters()
        self.adapters = adapters
        names = ["Wszystkie adaptery"] + [
            f"{a['description']}  [{', '.join(a['ips']) or 'brak IP'}]"
            for a in adapters
        ]
        self.adapter_cb["values"] = names
        self.adapter_cb.current(0)
        self.log_message(f"Znaleziono {len(adapters)} adapterów.")

    def log_message(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def on_device_found(self, info):
        """Callback wywoływany z wątku skanera — bezpieczny przez root.after."""
        self.root.after(0, self._add_device, info)

    def _add_device(self, info):
        # Unikamy duplikatów (ten sam IP + MAC)
        key = (info["ip"], info["mac"])
        if key in [(d["ip"], d["mac"]) for d in self.found_devices]:
            return

        self.found_devices.append(info)
        self.tree.insert("", "end", values=(
            info["ip"], info["mac"], info["keyword"], info["adapter"]
        ))
        self.log_message(f"✔ Znaleziono: {info['keyword']}  IP={info['ip']}  MAC={info['mac']}  [{info['adapter']}]")

    def toggle_scan(self):
        if not self.scanning:
            self._start_scan()
        else:
            self._stop_scan()

    def _start_scan(self):
        self.scanning = True
        self.stop_event.clear()
        self.btn_scan.config(text="⏹  Stop", bg="#c62828")
        self.status_var.set("⏳ Skanowanie w toku...")

        selected = self.adapter_cb.current()

        if selected == 0:
            # Wszystkie adaptery
            self.log_message("Uruchamiam skanowanie na wszystkich adapterach...")
            t = threading.Thread(
                target=start_scan_all,
                args=(self.on_device_found, self.stop_event),
                daemon=True
            )
            t.start()
        else:
            adapter = self.adapters[selected - 1]
            self.log_message(f"Uruchamiam skanowanie: {adapter['description']}...")
            t = threading.Thread(
                target=start_scan,
                args=(adapter["name"], self.on_device_found, self.stop_event),
                daemon=True
            )
            t.start()

    def _stop_scan(self):
        self.scanning = False
        self.stop_event.set()
        self.btn_scan.config(text="▶  Start", bg="#2e7d32")
        self.status_var.set("Zatrzymano.")
        self.log_message("Skanowanie zatrzymane.")

    def clear_results(self):
        self.found_devices.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.log_message("Wyniki wyczyszczone.")