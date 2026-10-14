"""
Hiraya Wifi Hotspot - turn your extra Wi-Fi receiver into a hotspot (Windows).

Uses the Windows "hosted network" feature (netsh wlan hostednetwork) on the
Wi-Fi adapter, and Internet Connection Sharing (ICS) to share the internet
from another adapter (e.g. Ethernet) to connected devices.

Requires Administrator rights - the app will ask to elevate on launch.
"""

import ctypes
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

import portal as captive

APP_NAME = "Hiraya Wifi Hotspot"
_APPDATA = os.environ.get("APPDATA", os.path.expanduser("~"))
CONFIG_DIR = os.path.join(_APPDATA, "HirayaWifiHotspot")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
VOUCHER_FILE = os.path.join(CONFIG_DIR, "vouchers.json")
OLD_CONFIG_FILE = os.path.join(_APPDATA, "WifiHotspot", "config.json")
CREATE_NO_WINDOW = 0x08000000
REFRESH_MS = 3000
DEFAULT_HOTSPOT_IP = "192.168.137.1"


# --------------------------------------------------------------------------- #
# Elevation
# --------------------------------------------------------------------------- #
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    if getattr(sys, "frozen", False):  # PyInstaller exe
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        exe = sys.executable.replace("python.exe", "pythonw.exe")
        if not os.path.exists(exe):
            exe = sys.executable
        params = " ".join(f'"{a}"' for a in [os.path.abspath(sys.argv[0])] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)


# --------------------------------------------------------------------------- #
# System helpers
# --------------------------------------------------------------------------- #
def run(cmd, env=None) -> tuple[int, str]:
    """Run a command hidden, return (exit code, combined output)."""
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=CREATE_NO_WINDOW,
        env=env,
        shell=isinstance(cmd, str),
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def powershell(script: str, extra_env: dict | None = None) -> tuple[int, str]:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], env=env)


def list_adapters() -> list[dict]:
    """All network adapters (name, description, status)."""
    code, out = powershell(
        "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status | ConvertTo-Json -Compress"
    )
    if code != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [
        {"name": d.get("Name", ""), "desc": d.get("InterfaceDescription", ""), "status": str(d.get("Status", ""))}
        for d in data
    ]


def hosted_adapter_name() -> str | None:
    for a in list_adapters():
        if "Hosted Network Virtual Adapter" in a["desc"]:
            return a["name"]
    return None


def hostednetwork_supported() -> bool:
    _, out = run("netsh wlan show drivers")
    return bool(re.search(r"Hosted network supported\s*:\s*Yes", out, re.I))


def hostednetwork_status() -> dict:
    _, out = run("netsh wlan show hostednetwork")
    status = re.search(r"^\s*Status\s*:\s*(.+)$", out, re.M)
    ssid = re.search(r'^\s*SSID name\s*:\s*"?(.*?)"?\s*$', out, re.M)
    macs = re.findall(r"^\s*((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+(\S+)", out, re.M | re.I)
    return {
        "status": status.group(1).strip() if status else "Unknown",
        "ssid": ssid.group(1) if ssid else "",
        "clients": [m[0].lower() for m in macs],
    }


def arp_lookup() -> dict:
    """MAC (aa:bb:..) -> IP from the ARP table."""
    _, out = run("arp -a")
    table = {}
    for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+((?:[0-9a-f]{2}-){5}[0-9a-f]{2})", out, re.I):
        table[mac.lower().replace("-", ":")] = ip
    return table


ICS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'

function Get-Cfgs {
    $m = New-Object -ComObject HNetCfg.HNetShare
    $list = @()
    foreach ($c in $m.EnumEveryConnection) {
        $list += [pscustomobject]@{
            Name = $m.NetConnectionProps.Invoke($c).Name
            Cfg  = $m.INetSharingConfigurationForINetConnection.Invoke($c)
        }
    }
    return $list
}

function Disable-All {
    foreach ($x in Get-Cfgs) {
        if ($x.Cfg.SharingEnabled) { try { $x.Cfg.DisableSharing() } catch {} }
    }
}

function Enable-Ics {
    $all = Get-Cfgs
    $public  = ($all | Where-Object Name -eq $env:HS_PUBLIC  | Select-Object -First 1).Cfg
    $private = ($all | Where-Object Name -eq $env:HS_PRIVATE | Select-Object -First 1).Cfg
    if (-not $public)  { throw "Source adapter '$env:HS_PUBLIC' not found" }
    if (-not $private) { throw "Hotspot adapter '$env:HS_PRIVATE' not found" }
    $public.EnableSharing(0)
    Start-Sleep -Milliseconds 800
    $private.EnableSharing(1)
}

function Clear-StaleIcs {
    # Ghost adapters (removed drivers, uninstalled VPN/hotspot apps) can stay flagged
    # as ICS public/private in WMI, which makes EnableSharing fail with 0x80040201.
    try {
        $live = @(Get-NetAdapter -IncludeHidden | ForEach-Object { $_.InterfaceGuid.ToUpper() })
        Get-WmiObject -Namespace root\Microsoft\HomeNet -Class HNet_ConnectionProperties |
            Where-Object { $_.IsIcsPublic -or $_.IsIcsPrivate } |
            ForEach-Object {
                if ($_.Connection -match '\{[0-9A-Fa-f-]+\}' -and ($live -notcontains $Matches[0].ToUpper())) {
                    $_.IsIcsPublic = $false; $_.IsIcsPrivate = $false; $_.Put() | Out-Null
                }
            }
    } catch {}
}

Clear-StaleIcs
Disable-All
if ($env:HS_MODE -eq 'enable') {
    $lastErr = $null
    for ($i = 1; $i -le 3; $i++) {
        try {
            Start-Sleep -Seconds 1
            Enable-Ics
            $lastErr = $null
            break
        } catch {
            $lastErr = $_
            # 0x80040201 etc: reset ICS service, then retry
            Disable-All
            Set-Service SharedAccess -StartupType Manual -ErrorAction SilentlyContinue
            Restart-Service SharedAccess -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    }
    if ($lastErr) { throw $lastErr }
}
'OK'
"""


def connectify_running() -> bool:
    _, out = run("tasklist /FO CSV /NH")
    return "connectify" in out.lower()


def set_ics(enable: bool, public: str = "", private: str = "") -> tuple[bool, str]:
    code, out = powershell(
        ICS_SCRIPT,
        {"HS_MODE": "enable" if enable else "disable", "HS_PUBLIC": public, "HS_PRIVATE": private},
    )
    ok = code == 0 and out.strip().endswith("OK")
    msg = out.strip()
    if not ok:
        first = next((l for l in msg.splitlines() if l.strip()), msg)
        msg = first
        if connectify_running():
            msg += ("\n\nConnectify is running and is blocking Windows Internet Sharing. "
                    "Quit Connectify completely (system tray → Exit), then try again.")
    return ok, msg


def start_hotspot(ssid: str, key: str, source: str) -> tuple[bool, str]:
    code, out = run(f'netsh wlan set hostednetwork mode=allow ssid="{ssid}" key="{key}" keyUsage=persistent')
    if code != 0:
        return False, out
    code, out = run("netsh wlan start hostednetwork")
    if code != 0:
        return False, out + "\n\nTip: make sure the Wi-Fi adapter is enabled and not turned off by Airplane mode."
    if source:
        private = hosted_adapter_name()
        if not private:
            return True, "Hotspot started, but the hosted network adapter could not be found for sharing."
        ok, msg = set_ics(True, source, private)
        if not ok:
            return True, f"Hotspot started, but internet sharing failed:\n{msg}"
    return True, "Hotspot started."


def stop_hotspot(disable_sharing: bool) -> tuple[bool, str]:
    code, out = run("netsh wlan stop hostednetwork")
    if disable_sharing:
        set_ics(False)
    return code == 0, out


def hotspot_ip() -> str:
    """IPv4 of the hosted network adapter (the ICS gateway), e.g. 192.168.137.1."""
    name = hosted_adapter_name()
    if name:
        code, out = powershell(f"(Get-NetIPAddress -InterfaceAlias '{name}' -AddressFamily IPv4 "
                               "-ErrorAction SilentlyContinue).IPAddress")
        m = re.search(r"\d+\.\d+\.\d+\.\d+", out)
        if m and not m.group(0).startswith("169.254."):
            return m.group(0)
    return DEFAULT_HOTSPOT_IP


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def load_config() -> dict:
    for path in (CONFIG_FILE, OLD_CONFIG_FILE):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            continue
    return {}


def save_config(cfg: dict) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


# --------------------------------------------------------------------------- #
# QR code
# --------------------------------------------------------------------------- #
QR_SIZE = 240
BIG_QR_SIZE = 460


def _qr_escape(s: str) -> str:
    for ch in ("\\", ";", ",", ":", '"'):
        s = s.replace(ch, "\\" + ch)
    return s


def wifi_qr_payload(ssid: str, key: str) -> str:
    """Standard Wi-Fi QR format understood by iPhone & Android cameras."""
    if key:
        return f"WIFI:T:WPA;S:{_qr_escape(ssid)};P:{_qr_escape(key)};;"
    return f"WIFI:T:nopass;S:{_qr_escape(ssid)};;"


def draw_qr(canvas: tk.Canvas, data: str, size: int) -> None:
    canvas.delete("all")
    if not data:
        canvas.create_text(size // 2, size // 2, text="Enter a network name", fill="#888")
        return
    try:
        import qrcode
    except ImportError:
        canvas.create_text(size // 2, size // 2, width=size - 20, fill="#c00", justify="center",
                           text="QR library missing.\nRun: pip install qrcode")
        return
    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    n = len(matrix)
    cell = size // n
    offset = (size - cell * n) // 2
    for y, row in enumerate(matrix):
        for x, on in enumerate(row):
            if on:
                x0, y0 = offset + x * cell, offset + y * cell
                canvas.create_rectangle(x0, y0, x0 + cell, y0 + cell, fill="black", outline="")


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #
BG, CARD, FG, MUTED, ACCENT, GREEN, RED = "#14161b", "#1d2027", "#e8eaed", "#9aa0a6", "#4f8cff", "#34c759", "#ff5f57"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("880x700")
        self.minsize(820, 640)
        self.configure(bg=BG)
        self.cfg = load_config()
        self.busy = False
        self.running = False
        self.portal_busy = False
        self.portal_error = ""
        self.clients: list[str] = []
        self.client_ips: dict[str, str] = {}
        self.store = captive.VoucherStore(VOUCHER_FILE)
        self.portal = captive.CaptivePortal(self.store, on_change=lambda: self.after(0, self.refresh_vouchers))
        self._style()
        self._build()
        self.after(100, self.refresh_adapters)
        self.after(300, self.poll)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---- styling ----
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, fieldbackground=CARD, font=("Segoe UI", 10))
        s.configure("Card.TFrame", background=CARD)
        s.configure("Card.TLabel", background=CARD, foreground=FG)
        s.configure("Muted.TLabel", background=CARD, foreground=MUTED, font=("Segoe UI", 9))
        s.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI Semibold", 18))
        s.configure("Sub.TLabel", background=BG, foreground=MUTED)
        s.configure("TEntry", fieldbackground="#262a33", foreground=FG, insertcolor=FG, bordercolor="#333844")
        s.configure("TCombobox", fieldbackground="#262a33", foreground=FG, background="#262a33", arrowcolor=FG)
        s.map("TCombobox", fieldbackground=[("readonly", "#262a33")], foreground=[("readonly", FG)])
        s.configure("TSpinbox", fieldbackground="#262a33", foreground=FG, background="#262a33", arrowcolor=FG)
        s.configure("Card.TCheckbutton", background=CARD, foreground=FG)
        s.map("Card.TCheckbutton", background=[("active", CARD)])
        s.configure("Treeview", background="#262a33", fieldbackground="#262a33", foreground=FG, rowheight=24,
                    borderwidth=0)
        s.configure("Treeview.Heading", background=CARD, foreground=MUTED, relief="flat")
        s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(16, 0, 16, 0))
        s.configure("TNotebook.Tab", background=CARD, foreground=MUTED, padding=(16, 6), borderwidth=0,
                    font=("Segoe UI Semibold", 10))
        s.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        self.option_add("*TCombobox*Listbox.background", "#262a33")
        self.option_add("*TCombobox*Listbox.foreground", FG)

    def _button(self, parent, text, command, primary=False, danger=False):
        bg = ACCENT if primary else RED if danger else "#262a33"
        abg = "#3d74e0" if primary else "#e04a43" if danger else "#333844"
        return tk.Button(parent, text=text, command=command, bg=bg, fg="white" if (primary or danger) else FG,
                         relief="flat", activebackground=abg, activeforeground="white", cursor="hand2",
                         padx=10, pady=4)

    def _card(self, parent, title):
        f = ttk.Frame(parent, style="Card.TFrame", padding=14)
        f.pack(fill="x", padx=16, pady=(0, 12))
        ttk.Label(f, text=title, style="Card.TLabel", font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(0, 8))
        return f

    # ---- layout ----
    def _build(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(16, 12))
        ttk.Label(header, text="📶  Hiraya Wifi Hotspot", style="Title.TLabel").pack(anchor="w")
        self.status_lbl = ttk.Label(header, text="Checking…", style="Sub.TLabel")
        self.status_lbl.pack(anchor="w")

        body_tabs = ttk.Notebook(self)
        body_tabs.pack(fill="both", expand=True)
        body = ttk.Frame(body_tabs)
        vouchers_tab = ttk.Frame(body_tabs)
        body_tabs.add(body, text="  Hotspot  ")
        body_tabs.add(vouchers_tab, text="  Vouchers  ")
        ttk.Frame(body, height=12).pack(fill="x")
        cols = ttk.Frame(body)
        cols.pack(fill="both", expand=True)
        left = ttk.Frame(cols)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(cols)
        right.pack(side="left", fill="y")

        # Settings
        c = self._card(left, "Hotspot settings")
        ttk.Label(c, text="Network name (SSID)", style="Muted.TLabel").pack(anchor="w")
        self.ssid = tk.StringVar(value=self.cfg.get("ssid", "MyHotspot"))
        ttk.Entry(c, textvariable=self.ssid).pack(fill="x", pady=(2, 8))

        ttk.Label(c, text="Password (8–63 characters)", style="Muted.TLabel").pack(anchor="w")
        self.key = tk.StringVar(value=self.cfg.get("key", ""))
        self.key_entry = ttk.Entry(c, textvariable=self.key, show="•")
        self.key_entry.pack(fill="x", pady=(2, 4))
        self.show_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(c, text="Show password", variable=self.show_key, style="Card.TCheckbutton",
                        command=self._on_show_key).pack(anchor="w", pady=(0, 8))

        ttk.Label(c, text="Share internet from", style="Muted.TLabel").pack(anchor="w")
        row = ttk.Frame(c, style="Card.TFrame")
        row.pack(fill="x", pady=(2, 0))
        self.source = tk.StringVar(value=self.cfg.get("source", ""))
        self.source_cb = ttk.Combobox(row, textvariable=self.source, state="readonly")
        self.source_cb.pack(side="left", fill="x", expand=True)
        tk.Button(row, text="⟳", command=self.refresh_adapters, bg="#262a33", fg=FG, relief="flat",
                  activebackground="#333844", activeforeground=FG, width=3).pack(side="left", padx=(6, 0))

        self.portal_on = tk.BooleanVar(value=self.cfg.get("portal", False))
        ttk.Checkbutton(c, text="Require voucher to get internet (captive portal)", variable=self.portal_on,
                        style="Card.TCheckbutton", command=self._on_portal_toggle).pack(anchor="w", pady=(10, 0))
        self.portal_lbl = ttk.Label(c, text="", style="Muted.TLabel")
        self.portal_lbl.pack(anchor="w")

        # Toggle button
        self.toggle_btn = tk.Button(left, text="Start Hotspot", command=self.toggle, font=("Segoe UI Semibold", 12),
                                    bg=ACCENT, fg="white", activebackground="#3d74e0", activeforeground="white",
                                    relief="flat", cursor="hand2", pady=10)
        self.toggle_btn.pack(fill="x", padx=16, pady=(0, 12))

        # Clients
        c = self._card(left, "Connected devices")
        c.pack_configure(fill="both", expand=True)
        self.tree = ttk.Treeview(c, columns=("mac", "ip", "access"), show="headings", height=4)
        self.tree.heading("mac", text="MAC address")
        self.tree.heading("ip", text="IP address")
        self.tree.heading("access", text="Access")
        self.tree.column("mac", width=150)
        self.tree.column("ip", width=110)
        self.tree.column("access", width=130)
        self.tree.pack(fill="both", expand=True)
        self._button(c, "Kick selected to portal", self.kick_selected).pack(anchor="e", pady=(8, 0))

        self._build_vouchers(vouchers_tab)

        # QR code
        c = self._card(right, "Scan to connect")
        c.pack_configure(padx=(0, 16), fill="both", expand=True)
        ttk.Label(c, text="Point your phone camera at the code", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.qr_canvas = tk.Canvas(c, width=QR_SIZE, height=QR_SIZE, bg="white", highlightthickness=0)
        self.qr_canvas.pack()
        self.qr_ssid_lbl = ttk.Label(c, text="", style="Card.TLabel", font=("Segoe UI Semibold", 11))
        self.qr_ssid_lbl.pack(pady=(10, 0))
        self.qr_key_lbl = ttk.Label(c, text="", style="Muted.TLabel")
        self.qr_key_lbl.pack()
        tk.Button(c, text="⛶  Enlarge", command=self.show_big_qr, bg="#262a33", fg=FG, relief="flat",
                  activebackground="#333844", activeforeground=FG, cursor="hand2").pack(fill="x", pady=(10, 0))

        self.ssid.trace_add("write", lambda *_: self.update_qr())
        self.key.trace_add("write", lambda *_: self.update_qr())
        self.update_qr()

    # ---- Vouchers tab ----
    def _build_vouchers(self, tab):
        ttk.Frame(tab, height=12).pack(fill="x")
        c = self._card(tab, "Create vouchers")
        row = ttk.Frame(c, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="Duration", style="Muted.TLabel").pack(side="left")
        self.v_duration = ttk.Combobox(row, state="readonly", width=14,
                                       values=[label for label, _ in captive.DURATIONS])
        self.v_duration.current(2)
        self.v_duration.pack(side="left", padx=(6, 16))
        ttk.Label(row, text="Quantity", style="Muted.TLabel").pack(side="left")
        self.v_qty = tk.IntVar(value=5)
        ttk.Spinbox(row, from_=1, to=100, textvariable=self.v_qty, width=5).pack(side="left", padx=(6, 16))
        self._button(row, "Generate", self.generate_vouchers, primary=True).pack(side="left")
        self.v_summary = ttk.Label(c, text="", style="Muted.TLabel")
        self.v_summary.pack(anchor="w", pady=(8, 0))

        c = self._card(tab, "Vouchers")
        c.pack_configure(fill="both", expand=True)
        filt = ttk.Frame(c, style="Card.TFrame")
        filt.pack(fill="x", pady=(0, 6))
        ttk.Label(filt, text="Show", style="Muted.TLabel").pack(side="left")
        self.v_filter = ttk.Combobox(filt, state="readonly", width=10,
                                     values=["All", "Unused", "Active", "Queued", "Expired", "Ended"])
        self.v_filter.current(0)
        self.v_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_vouchers())
        self.v_filter.pack(side="left", padx=6)

        frame = ttk.Frame(c, style="Card.TFrame")
        frame.pack(fill="both", expand=True)
        cols = ("code", "duration", "status", "left", "device", "created")
        self.vtree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
        for col, title, w in (("code", "Code", 90), ("duration", "Duration", 90), ("status", "Status", 80),
                              ("left", "Time left", 100), ("device", "Device", 140), ("created", "Created", 130)):
            self.vtree.heading(col, text=title)
            self.vtree.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.vtree.yview)
        self.vtree.configure(yscrollcommand=sb.set)
        self.vtree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.vtree.tag_configure("Active", foreground=GREEN)
        self.vtree.tag_configure("Queued", foreground="#ffd60a")
        self.vtree.tag_configure("Expired", foreground=MUTED)
        self.vtree.tag_configure("Ended", foreground=MUTED)

        btns = ttk.Frame(c, style="Card.TFrame")
        btns.pack(fill="x", pady=(8, 0))
        self._button(btns, "Copy codes", self.copy_vouchers).pack(side="left")
        self._button(btns, "Print selected / unused", self.print_vouchers).pack(side="left", padx=6)
        self._button(btns, "End session", self.end_vouchers).pack(side="left")
        self._button(btns, "Delete", self.delete_vouchers, danger=True).pack(side="right")
        self._button(btns, "Clear used", self.clear_used_vouchers).pack(side="right", padx=6)
        self.refresh_vouchers()

    def selected_codes(self) -> list[str]:
        return [self.vtree.item(i, "values")[0] for i in self.vtree.selection()]

    def generate_vouchers(self):
        minutes = captive.DURATIONS[self.v_duration.current()][1]
        try:
            qty = max(1, min(100, int(self.v_qty.get())))
        except (tk.TclError, ValueError):
            qty = 1
        codes = self.store.generate(qty, minutes)
        self.refresh_vouchers()
        for item in self.vtree.get_children():
            if self.vtree.item(item, "values")[0] in codes:
                self.vtree.selection_add(item)

    def refresh_vouchers(self):
        if not hasattr(self, "vtree"):
            return
        selected = set(self.selected_codes())
        flt = self.v_filter.get()
        now = time.time()
        self.vtree.delete(*self.vtree.get_children())
        counts = {}
        for v in self.store.all():
            st = self.store.status(v, now)
            counts[st] = counts.get(st, 0) + 1
            if flt != "All" and st != flt:
                continue
            left = captive.fmt_remaining(self.store.remaining(v, now)) if st in ("Active", "Queued") else ""
            item = self.vtree.insert("", "end", tags=(st,), values=(
                v["code"], captive.fmt_minutes(v["minutes"]), st, left, v.get("mac") or "",
                time.strftime("%b %d %H:%M", time.localtime(v["created"]))))
            if v["code"] in selected:
                self.vtree.selection_add(item)
        self.v_summary.configure(text="   ".join(f"{k}: {counts.get(k, 0)}"
                                               for k in ("Unused", "Active", "Queued", "Expired", "Ended")))

    def copy_vouchers(self):
        codes = self.selected_codes() or [v["code"] for v in self.store.all() if self.store.status(v) == "Unused"]
        if not codes:
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(codes))
        messagebox.showinfo(APP_NAME, f"Copied {len(codes)} code(s) to clipboard.")

    def end_vouchers(self):
        codes = self.selected_codes()
        if codes and messagebox.askyesno(APP_NAME, f"End {len(codes)} voucher session(s) now?"):
            for c in codes:
                self.store.end(c)
            self.refresh_vouchers()

    def delete_vouchers(self):
        codes = self.selected_codes()
        if codes and messagebox.askyesno(APP_NAME, f"Delete {len(codes)} voucher(s)? Active devices lose access."):
            self.store.delete(codes)
            self.refresh_vouchers()

    def clear_used_vouchers(self):
        self.store.delete_used()
        self.refresh_vouchers()

    def print_vouchers(self):
        codes = set(self.selected_codes())
        if codes:
            vouchers = [v for v in self.store.all() if v["code"] in codes]
        else:
            vouchers = [v for v in self.store.all() if self.store.status(v) == "Unused"]
        if not vouchers:
            return messagebox.showinfo(APP_NAME, "No vouchers to print. Generate some first.")
        ssid = html.escape(self.ssid.get().strip())
        key = html.escape(self.key.get())
        cards = "".join(
            f'<div class="v"><div class="t">📶 Hiraya Wifi</div><div class="c">{v["code"]}</div>'
            f'<div class="d">{captive.fmt_minutes(v["minutes"])}</div>'
            f'<div class="n">Wi-Fi: <b>{ssid}</b><br>Password: <b>{key}</b></div></div>'
            for v in vouchers)
        page = f"""<!doctype html><html><head><meta charset="utf-8"><title>Hiraya Wifi Vouchers</title>
<style>body{{font-family:Segoe UI,sans-serif;margin:20px}}
.g{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}}
.v{{border:2px dashed #555;border-radius:10px;padding:12px;text-align:center;break-inside:avoid}}
.t{{font-weight:600;color:#2b3a8f}}.c{{font-size:28px;font-weight:700;letter-spacing:4px;margin:6px 0}}
.d{{font-size:14px;background:#eef;border-radius:6px;padding:2px 0;margin-bottom:6px}}.n{{font-size:11px;color:#444}}
@media print{{button{{display:none}}}}</style></head><body>
<button onclick="print()" style="margin-bottom:14px;padding:8px 16px">🖨 Print</button>
<div class="g">{cards}</div></body></html>"""
        path = os.path.join(tempfile.gettempdir(), "hiraya_vouchers.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(page)
        webbrowser.open(f"file:///{path}")

    def kick_selected(self):
        macs = [self.tree.item(i, "values")[0] for i in self.tree.selection()]
        if not macs:
            return messagebox.showinfo(APP_NAME, "Select a device in the list first.")
        for mac in macs:
            self.store.end_device(mac)
        self.refresh_vouchers()

    # ---- captive portal lifecycle ----
    def _on_portal_toggle(self):
        self.cfg["portal"] = self.portal_on.get()
        save_config(self.cfg)
        if self.portal_on.get() and not self.selected_source():
            messagebox.showwarning(APP_NAME, "The captive portal needs internet sharing. "
                                             "Choose an adapter under 'Share internet from'.")
        self.portal_error = ""
        self.sync_portal()

    def sync_portal(self):
        """Start/stop the portal so it matches (hotspot running AND portal enabled)."""
        if self.portal_busy or self.busy:
            return
        want = self.running and self.portal_on.get() and bool(self.selected_source())
        if want and not self.portal.running and not self.portal_error:
            self.portal_busy = True

            def work():
                ok, msg = self.portal.start(hotspot_ip())
                self.after(0, lambda: self._portal_started(ok, msg))
            threading.Thread(target=work, daemon=True).start()
        elif not want and self.portal.running:
            self.portal_busy = True

            def work():
                self.portal.stop()
                self.after(0, self._portal_stopped)
            threading.Thread(target=work, daemon=True).start()
        self._update_portal_label()

    def _portal_started(self, ok, msg):
        self.portal_busy = False
        if not ok:
            self.portal_error = msg
            messagebox.showerror(APP_NAME, msg)
        self._update_portal_label()

    def _portal_stopped(self):
        self.portal_busy = False
        self._update_portal_label()

    def _update_portal_label(self):
        if self.portal.running:
            self.portal_lbl.configure(text=f"Portal active at http://{self.portal.ip}/  ·  "
                                           f"guests must enter a voucher", foreground=GREEN)
        elif self.portal_busy:
            self.portal_lbl.configure(text="Starting portal…", foreground=MUTED)
        elif self.portal_error:
            self.portal_lbl.configure(text="Portal failed to start (toggle to retry)", foreground=RED)
        elif self.portal_on.get():
            self.portal_lbl.configure(text="Portal will start with the hotspot", foreground=MUTED)
        else:
            self.portal_lbl.configure(text="Off: anyone with the Wi-Fi password gets internet", foreground=MUTED)

    # ---- QR code ----
    def _on_show_key(self):
        self.key_entry.configure(show="" if self.show_key.get() else "•")
        self.update_qr()

    def update_qr(self):
        ssid, key = self.ssid.get().strip(), self.key.get()
        draw_qr(self.qr_canvas, wifi_qr_payload(ssid, key) if ssid else "", QR_SIZE)
        self.qr_ssid_lbl.configure(text=ssid or "(no network name)")
        shown = key if self.show_key.get() else "•" * len(key)
        self.qr_key_lbl.configure(text=f"Password: {shown}" if key else "Open network")
        if getattr(self, "big_qr", None) and self.big_qr.winfo_exists():
            self._draw_big_qr()

    def show_big_qr(self):
        if getattr(self, "big_qr", None) and self.big_qr.winfo_exists():
            self.big_qr.lift()
            return
        self.big_qr = tk.Toplevel(self)
        self.big_qr.title(f"{APP_NAME} — Scan to connect")
        self.big_qr.configure(bg="white")
        self.big_qr.resizable(False, False)
        self.big_canvas = tk.Canvas(self.big_qr, width=BIG_QR_SIZE, height=BIG_QR_SIZE, bg="white",
                                    highlightthickness=0)
        self.big_canvas.pack(padx=30, pady=(30, 10))
        self.big_lbl = tk.Label(self.big_qr, bg="white", fg="#111", font=("Segoe UI Semibold", 16))
        self.big_lbl.pack(pady=(0, 4))
        self.big_key_lbl = tk.Label(self.big_qr, bg="white", fg="#555", font=("Segoe UI", 12))
        self.big_key_lbl.pack(pady=(0, 24))
        self._draw_big_qr()

    def _draw_big_qr(self):
        ssid, key = self.ssid.get().strip(), self.key.get()
        draw_qr(self.big_canvas, wifi_qr_payload(ssid, key) if ssid else "", BIG_QR_SIZE)
        self.big_lbl.configure(text=f"📶  {ssid}")
        self.big_key_lbl.configure(text=f"Password: {key}" if key else "Open network")

    # ---- actions ----
    def refresh_adapters(self):
        def work():
            adapters = [a for a in list_adapters()
                        if "Hosted Network" not in a["desc"] and "Wi-Fi Direct" not in a["desc"]]
            self.after(0, lambda: self._set_adapters(adapters))
        threading.Thread(target=work, daemon=True).start()

    def _set_adapters(self, adapters):
        self.adapters = adapters
        values = ["(Don't share internet)"] + [f"{a['name']}  —  {a['desc']}  [{a['status']}]" for a in adapters]
        self.source_cb["values"] = values
        current = self.cfg.get("source", "")
        idx = next((i + 1 for i, a in enumerate(adapters) if a["name"] == current), None)
        if idx is None:  # default: first connected non-wifi adapter
            idx = next((i + 1 for i, a in enumerate(adapters)
                        if a["status"] == "Up" and "Wireless" not in a["desc"] and "Wi-Fi" not in a["name"]
                        and "Virtual" not in a["desc"] and "Tunnel" not in a["desc"]), 0)
        self.source_cb.current(idx)

    def selected_source(self) -> str:
        i = self.source_cb.current()
        return self.adapters[i - 1]["name"] if i and i > 0 else ""

    def toggle(self):
        if self.busy:
            return
        if self.running:
            def stop_all():
                self.portal.stop()
                return stop_hotspot(disable_sharing=True)
            self._run_task(stop_all, "Stopping…")
            return

        ssid, key = self.ssid.get().strip(), self.key.get()
        if not ssid or len(ssid) > 32 or '"' in ssid:
            return messagebox.showerror(APP_NAME, "SSID must be 1–32 characters and contain no quotes.")
        if not (8 <= len(key) <= 63) or '"' in key:
            return messagebox.showerror(APP_NAME, "Password must be 8–63 characters and contain no quotes.")
        source = self.selected_source()
        if source and connectify_running() and not messagebox.askyesno(
                APP_NAME, "Connectify is running and usually blocks Windows Internet Sharing.\n\n"
                          "Quit Connectify from the system tray first for best results.\n\nStart anyway?"):
            return
        self.cfg.update(ssid=ssid, key=key, source=source)
        save_config(self.cfg)
        self.portal_error = ""
        self._run_task(lambda: start_hotspot(ssid, key, source), "Starting…", show_result=True)

    def _run_task(self, fn, label, show_result=False):
        self.busy = True
        self.toggle_btn.configure(text=label, state="disabled")

        def work():
            ok, msg = fn()
            self.after(0, lambda: self._task_done(ok, msg, show_result))
        threading.Thread(target=work, daemon=True).start()

    def _task_done(self, ok, msg, show_result):
        self.busy = False
        self.toggle_btn.configure(state="normal")
        if not ok:
            messagebox.showerror(APP_NAME, msg.strip() or "Operation failed.")
        elif show_result and msg != "Hotspot started.":
            messagebox.showwarning(APP_NAME, msg)
        self.poll(reschedule=False)

    # ---- status polling ----
    def poll(self, reschedule=True):
        def work():
            st = hostednetwork_status()
            arp = arp_lookup() if st["clients"] else {}
            self.after(0, lambda: self._update_status(st, arp))
        threading.Thread(target=work, daemon=True).start()
        if reschedule:
            self.after(REFRESH_MS, self.poll)

    def _update_status(self, st, arp):
        self.running = st["status"].lower() == "started"
        n = len(st["clients"])
        if self.running:
            self.status_lbl.configure(text=f"●  Broadcasting \"{st['ssid']}\"  ·  {n} device(s)", foreground=GREEN)
        else:
            self.status_lbl.configure(text=f"●  Hotspot off ({st['status']})", foreground=RED)
        if not self.busy:
            self.toggle_btn.configure(
                text="Stop Hotspot" if self.running else "Start Hotspot",
                bg=RED if self.running else ACCENT,
                activebackground="#e04a43" if self.running else "#3d74e0",
            )
        selected = {self.tree.item(i, "values")[0] for i in self.tree.selection()}
        self.tree.delete(*self.tree.get_children())
        now = time.time()
        for mac in st["clients"]:
            if self.portal.running:
                end = self.store.device_end(mac, now)
                access = f"✓ {captive.fmt_remaining(end - now)} left" if end > now else "Waiting for voucher"
            else:
                access = "Open"
            item = self.tree.insert("", "end", values=(mac, arp.get(mac, "assigning…"), access))
            if mac in selected:
                self.tree.selection_add(item)
        self.refresh_vouchers()
        self.sync_portal()

    def on_close(self):
        if self.running:
            ans = messagebox.askyesnocancel(
                APP_NAME, "Stop the hotspot before closing?\n\n"
                          "If you keep it running, the voucher portal still stops when the app closes, "
                          "so connected devices will get internet freely.")
            if ans is None:
                return
            self.portal.stop()
            if ans:
                stop_hotspot(disable_sharing=True)
        else:
            self.portal.stop()
        self.destroy()


def main():
    if not is_admin():
        relaunch_as_admin()
        return
    if not hostednetwork_supported():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(APP_NAME, "Your Wi-Fi adapter driver does not support Hosted Network.\n"
                                       "Try updating the adapter driver.")
        return
    App().mainloop()


if __name__ == "__main__":
    main()
