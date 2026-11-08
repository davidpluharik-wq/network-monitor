#!/usr/bin/env python3
"""
Network Monitor GUI
--------------------
A desktop app (Tkinter) that periodically scans your local network with
nmap and shows you connected devices, alerting when a new one appears.

Requirements:
  - nmap installed:  sudo apt install nmap
  - tkinter (usually pre-installed; if missing: sudo apt install python3-tk)

IMPORTANT — running with sudo (for MAC/vendor detection via ARP scan):
GUI apps run with `sudo` sometimes can't open the display. If you hit a
"cannot open display" error, run it like this instead so root can still
use your X session:

    sudo -E env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 network_monitor_gui.py

Or run it as a normal user (no sudo) — it'll still work, you'll just get
IP addresses without MAC/vendor info, since raw ARP scanning needs root.
"""

import json
import queue
import re
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from pathlib import Path

STATE_FILE = Path.home() / ".network_monitor_known_devices.json"
LOG_FILE = Path.home() / "network_monitor.log"


# ---------------------------------------------------------------------------
# Core scanning logic (same approach as the CLI version)
# ---------------------------------------------------------------------------

def run_nmap_scan(network: str):
    cmd = ["nmap", "-sn", network]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        return None, "nmap is not installed. Install it with: sudo apt install nmap"
    except subprocess.TimeoutExpired:
        return None, "nmap scan timed out."

    if result.returncode != 0:
        return None, f"nmap error:\n{result.stderr.strip()}"

    return parse_nmap_output(result.stdout), None


def parse_nmap_output(output: str) -> dict:
    devices = {}
    current_ip = None

    ip_pattern = re.compile(r"Nmap scan report for (?:(\S+) \()?([\d\.]+)\)?")
    mac_pattern = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17}) \(?([^)]*)\)?")

    for line in output.splitlines():
        ip_match = ip_pattern.search(line)
        if ip_match:
            current_hostname = ip_match.group(1)
            current_ip = ip_match.group(2)
            devices[current_ip] = {
                "mac": None,
                "vendor": None,
                "hostname": current_hostname,
                "first_seen": None,  # filled in by caller
            }
            continue

        mac_match = mac_pattern.search(line)
        if mac_match and current_ip:
            devices[current_ip]["mac"] = mac_match.group(1)
            devices[current_ip]["vendor"] = mac_match.group(2) or None

    return devices


def load_known_devices() -> dict:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_known_devices(devices: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(devices, f, indent=2)


def log_to_file(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


# ---------------------------------------------------------------------------
# Background scanning worker (runs in its own thread, talks to GUI via queue)
# ---------------------------------------------------------------------------

class ScannerThread(threading.Thread):
    def __init__(self, network: str, interval: int, event_queue: queue.Queue, known_devices: dict):
        super().__init__(daemon=True)
        self.network = network
        self.interval = interval
        self.event_queue = event_queue
        self.known_devices = known_devices
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    def run(self):
        while not self._stop_flag.is_set():
            self.event_queue.put(("status", f"Scanning {self.network} ..."))
            devices, error = run_nmap_scan(self.network)

            if error:
                self.event_queue.put(("error", error))
            elif devices:
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                new_ips = [ip for ip in devices if ip not in self.known_devices]

                for ip in devices:
                    if ip in self.known_devices:
                        # keep original first_seen, refresh other info
                        devices[ip]["first_seen"] = self.known_devices[ip].get("first_seen", now_str)
                    else:
                        devices[ip]["first_seen"] = now_str

                self.known_devices.update(devices)
                save_known_devices(self.known_devices)

                self.event_queue.put(("devices", dict(self.known_devices)))

                if new_ips:
                    for ip in new_ips:
                        self.event_queue.put(("new_device", (ip, devices[ip])))
                else:
                    self.event_queue.put(("status", f"No new devices. {len(devices)} online."))
            else:
                self.event_queue.put(("status", "No devices found this scan."))

            # Sleep in small increments so stop() is responsive
            slept = 0
            while slept < self.interval and not self._stop_flag.is_set():
                time.sleep(1)
                slept += 1


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor")
        self.root.geometry("820x520")
        self.root.minsize(700, 420)

        self.event_queue = queue.Queue()
        self.known_devices = load_known_devices()
        self.scanner_thread = None
        self.row_ips = {}  # maps treeview item id -> ip

        self._build_ui()
        self._poll_queue()

        if self.known_devices:
            self._refresh_device_table(self.known_devices)
            self._log(f"Loaded {len(self.known_devices)} previously known device(s).")

    # ---------------- UI construction ----------------

    def _build_ui(self):
        controls = ttk.Frame(self.root, padding=10)
        controls.pack(fill="x")

        ttk.Label(controls, text="Network:").grid(row=0, column=0, sticky="w")
        self.network_entry = ttk.Entry(controls, width=20)
        self.network_entry.insert(0, "192.168.1.0/24")
        self.network_entry.grid(row=0, column=1, padx=(5, 15))

        ttk.Label(controls, text="Interval (sec):").grid(row=0, column=2, sticky="w")
        self.interval_entry = ttk.Entry(controls, width=8)
        self.interval_entry.insert(0, "600")
        self.interval_entry.grid(row=0, column=3, padx=(5, 15))

        self.start_button = ttk.Button(controls, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=0, column=4, padx=5)

        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop_monitoring, state="disabled")
        self.stop_button.grid(row=0, column=5, padx=5)

        self.status_label = ttk.Label(self.root, text="Idle.", padding=(10, 0), foreground="#555")
        self.status_label.pack(fill="x")

        # Device table
        table_frame = ttk.Frame(self.root, padding=(10, 5))
        table_frame.pack(fill="both", expand=True)

        columns = ("ip", "hostname", "mac", "vendor", "first_seen")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=10)
        for col, label, width in [
            ("ip", "IP Address", 120),
            ("hostname", "Hostname", 150),
            ("mac", "MAC Address", 140),
            ("vendor", "Vendor", 160),
            ("first_seen", "First Seen", 150),
        ]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")

        self.tree.tag_configure("new", background="#fff3b0")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Log area
        log_frame = ttk.Frame(self.root, padding=(10, 5))
        log_frame.pack(fill="both", expand=False)

        ttk.Label(log_frame, text="Activity Log:").pack(anchor="w")
        self.log_text = tk.Text(log_frame, height=8, state="disabled", wrap="word", bg="#111", fg="#ddd")
        self.log_text.pack(fill="both", expand=True)

    # ---------------- Actions ----------------

    def start_monitoring(self):
        network = self.network_entry.get().strip()
        try:
            interval = int(self.interval_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid interval", "Interval must be a whole number of seconds.")
            return

        if not network:
            messagebox.showerror("Missing network", "Please enter a network range, e.g. 192.168.1.0/24")
            return

        self.scanner_thread = ScannerThread(network, interval, self.event_queue, self.known_devices)
        self.scanner_thread.start()

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.network_entry.config(state="disabled")
        self.interval_entry.config(state="disabled")
        self._log(f"Started monitoring {network} every {interval}s.")

    def stop_monitoring(self):
        if self.scanner_thread:
            self.scanner_thread.stop()
            self.scanner_thread = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.network_entry.config(state="normal")
        self.interval_entry.config(state="normal")
        self.status_label.config(text="Stopped.")
        self._log("Stopped monitoring.")

    # ---------------- Queue polling (runs on main thread) ----------------

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()

                if kind == "status":
                    self.status_label.config(text=payload)
                    self._log(payload)
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self._log(f"ERROR: {payload}")
                elif kind == "devices":
                    self._refresh_device_table(payload)
                elif kind == "new_device":
                    ip, info = payload
                    self._handle_new_device(ip, info)

        except queue.Empty:
            pass

        self.root.after(200, self._poll_queue)

    # ---------------- Helpers ----------------

    def _refresh_device_table(self, devices: dict):
        self.tree.delete(*self.tree.get_children())
        self.row_ips.clear()

        for ip, info in sorted(devices.items(), key=lambda kv: tuple(int(p) for p in kv[0].split("."))):
            item_id = self.tree.insert("", "end", values=(
                ip,
                info.get("hostname") or "-",
                info.get("mac") or "-",
                info.get("vendor") or "-",
                info.get("first_seen") or "-",
            ))
            self.row_ips[item_id] = ip

    def _handle_new_device(self, ip: str, info: dict):
        description = f"{ip}"
        if info.get("hostname"):
            description += f" ({info['hostname']})"
        if info.get("vendor"):
            description += f" — {info['vendor']}"

        self._log(f"NEW DEVICE DETECTED: {description}")
        log_to_file(f"NEW DEVICE DETECTED: {description}")

        # Highlight it in the table temporarily
        for item_id, item_ip in self.row_ips.items():
            if item_ip == ip:
                self.tree.item(item_id, tags=("new",))

        # Try a native desktop notification too (best-effort, ignored if unavailable)
        try:
            subprocess.run(["notify-send", "New device on your network!", description], check=False, timeout=5)
        except Exception:
            pass

        messagebox.showinfo("New Device Detected", description)

    def _log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


def main():
    root = tk.Tk()
    app = NetworkMonitorApp(root)

    def on_close():
        if app.scanner_thread:
            app.scanner_thread.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
