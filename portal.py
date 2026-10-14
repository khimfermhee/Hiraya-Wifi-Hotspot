"""
Hiraya Wifi Hotspot - captive portal with time-limited vouchers.

How it works (a "soft" DNS-based portal, the only option on top of Windows ICS):
  * A DNS server on the hotspot IP answers every lookup from unapproved devices
    with the hotspot IP, so all web traffic lands on our HTTP server.
  * The HTTP server answers the phone/PC "captive portal detection" probes with a
    redirect, which makes the device pop up its "Sign in to network" screen.
  * After a device redeems a valid voucher, its DNS queries are forwarded to a
    real upstream resolver until the voucher time runs out.
Devices are identified by MAC address (looked up from the ARP table), so a
session survives IP changes.
"""

import html
import json
import os
import random
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

CREATE_NO_WINDOW = 0x08000000
PORTAL_HOSTNAME = "hiraya.wifi"
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O/1/I/L confusion
CODE_LEN = 6
MAX_FORWARD_TTL = 60  # seconds; keeps revoked devices from using cached DNS for long
FALLBACK_DNS = ["1.1.1.1", "8.8.8.8"]

DURATIONS = [  # (label, minutes)
    ("15 minutes", 15), ("30 minutes", 30), ("1 hour", 60), ("2 hours", 120), ("3 hours", 180),
    ("6 hours", 360), ("12 hours", 720), ("1 day", 1440), ("3 days", 4320), ("7 days", 10080),
    ("30 days", 43200),
]


def _run(cmd: str) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                       creationflags=CREATE_NO_WINDOW, shell=True)
    return (p.stdout or "") + (p.stderr or "")


def fmt_minutes(minutes: int) -> str:
    for label, m in DURATIONS:
        if m == minutes:
            return label
    if minutes % 1440 == 0:
        return f"{minutes // 1440} day(s)"
    if minutes % 60 == 0:
        return f"{minutes // 60} hour(s)"
    return f"{minutes} min"


def fmt_remaining(seconds: float) -> str:
    s = max(0, int(seconds))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# --------------------------------------------------------------------------- #
# Vouchers
# --------------------------------------------------------------------------- #
class VoucherStore:
    """
    Voucher fields:
      code, minutes, created, activated (epoch or None), start (epoch session start),
      mac, ended (bool, manually revoked)
    Redeeming a second voucher on a device that still has time queues it after the
    current one, so time stacks.
    """

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.vouchers: dict[str, dict] = {}
        self.load()

    # ---- persistence ----
    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.vouchers = {v["code"]: v for v in json.load(f)}
        except Exception:
            self.vouchers = {}

    def save(self):
        with self.lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(list(self.vouchers.values()), f, indent=2)
            os.replace(tmp, self.path)

    # ---- state helpers ----
    @staticmethod
    def end_time(v: dict) -> float | None:
        return v["start"] + v["minutes"] * 60 if v.get("start") else None

    def status(self, v: dict, now: float | None = None) -> str:
        now = now or time.time()
        if v.get("ended"):
            return "Ended"
        if not v.get("activated"):
            return "Unused"
        end = self.end_time(v)
        if now >= end:
            return "Expired"
        if now < v["start"]:
            return "Queued"
        return "Active"

    def remaining(self, v: dict, now: float | None = None) -> float:
        now = now or time.time()
        if self.status(v, now) not in ("Active", "Queued"):
            return 0
        return self.end_time(v) - max(now, v["start"])

    # ---- operations ----
    def generate(self, count: int, minutes: int) -> list[str]:
        codes = []
        with self.lock:
            for _ in range(count):
                while True:
                    code = "".join(random.SystemRandom().choice(CODE_ALPHABET) for _ in range(CODE_LEN))
                    if code not in self.vouchers:
                        break
                self.vouchers[code] = {"code": code, "minutes": minutes, "created": time.time(),
                                       "activated": None, "start": None, "mac": None, "ended": False}
                codes.append(code)
            self.save()
        return codes

    def device_end(self, mac: str, now: float | None = None) -> float:
        """Epoch when the device's (stacked) access ends, or 0."""
        now = now or time.time()
        end = 0.0
        with self.lock:
            for v in self.vouchers.values():
                if v.get("mac") == mac and self.status(v, now) in ("Active", "Queued"):
                    end = max(end, self.end_time(v))
        return end

    def is_authorized(self, mac: str | None) -> bool:
        return bool(mac) and self.device_end(mac) > time.time()

    def redeem(self, raw_code: str, mac: str) -> tuple[bool, str]:
        code = re.sub(r"[^A-Za-z0-9]", "", raw_code or "").upper()
        now = time.time()
        with self.lock:
            v = self.vouchers.get(code)
            if not v:
                return False, "Invalid voucher code. Please check and try again."
            st = self.status(v, now)
            if st in ("Expired", "Ended"):
                return False, "This voucher has already been used up."
            if st in ("Active", "Queued"):
                if v["mac"] == mac:
                    return True, "This voucher is already active on your device."
                return False, "This voucher is already in use on another device."
            # Unused -> activate (stack after any existing time on this device)
            current_end = self.device_end(mac, now)
            v["activated"] = now
            v["start"] = max(now, current_end)
            v["mac"] = mac
            self.save()
            added = fmt_minutes(v["minutes"])
            return True, f"{added} added." if current_end > now else f"Connected for {added}."

    def end(self, code: str):
        with self.lock:
            if code in self.vouchers:
                self.vouchers[code]["ended"] = True
                self.save()

    def end_device(self, mac: str):
        with self.lock:
            for v in self.vouchers.values():
                if v.get("mac") == mac and self.status(v) in ("Active", "Queued"):
                    v["ended"] = True
            self.save()

    def delete(self, codes: list[str]):
        with self.lock:
            for c in codes:
                self.vouchers.pop(c, None)
            self.save()

    def delete_used(self):
        with self.lock:
            now = time.time()
            for c in [c for c, v in self.vouchers.items() if self.status(v, now) in ("Expired", "Ended")]:
                self.vouchers.pop(c)
            self.save()

    def all(self) -> list[dict]:
        with self.lock:
            return sorted(self.vouchers.values(), key=lambda v: v["created"], reverse=True)


# --------------------------------------------------------------------------- #
# ARP (IP -> MAC)
# --------------------------------------------------------------------------- #
class ArpCache:
    def __init__(self):
        self.table: dict[str, str] = {}
        self.last = 0.0
        self.lock = threading.Lock()

    def refresh(self, force=False):
        with self.lock:
            if not force and time.time() - self.last < 1.0:
                return
            self.last = time.time()
        out = _run("arp -a")
        table = {}
        for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+((?:[0-9a-f]{2}-){5}[0-9a-f]{2})", out, re.I):
            table[ip] = mac.lower().replace("-", ":")
        with self.lock:
            self.table = table

    def mac_for(self, ip: str) -> str | None:
        mac = self.table.get(ip)
        if not mac:
            self.refresh()
            mac = self.table.get(ip)
        return mac


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
def _skip_name(buf: bytes, off: int) -> int:
    while True:
        ln = buf[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += ln + 1


def _read_qname(buf: bytes, off: int) -> str:
    labels = []
    while True:
        ln = buf[off]
        if ln == 0 or ln & 0xC0:
            break
        labels.append(buf[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += ln + 1
    return ".".join(labels).lower()


def _cap_ttls(resp: bytes, cap: int) -> bytes:
    try:
        b = bytearray(resp)
        qd, an, ns, ar = struct.unpack(">HHHH", b[4:12])
        off = 12
        for _ in range(qd):
            off = _skip_name(b, off) + 4
        for _ in range(an + ns + ar):
            off = _skip_name(b, off)
            rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", b[off:off + 10])
            if rtype != 41 and ttl > cap:  # 41 = OPT (ttl field is flags)
                struct.pack_into(">I", b, off + 4, cap)
            off += 10 + rdlen
        return bytes(b)
    except Exception:
        return resp


def _hijack_answer(query: bytes, ip: str) -> bytes | None:
    if len(query) < 12:
        return None
    qid, flags, qd = struct.unpack(">HHH", query[:6])
    if qd != 1:
        return None
    qend = _skip_name(query, 12)
    qtype = struct.unpack(">H", query[qend:qend + 2])[0]
    question = query[12:qend + 4]
    rflags = 0x8000 | (flags & 0x7900) | 0x0080  # QR + opcode/RD + RA
    if qtype == 1:  # A
        header = struct.pack(">HHHHHH", qid, rflags, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + socket.inet_aton(ip)
        return header + question + answer
    header = struct.pack(">HHHHHH", qid, rflags, 1, 0, 0, 0)  # NOERROR, no data (AAAA etc.)
    return header + question


def detect_upstream_dns(exclude: str) -> list[str]:
    out = _run('powershell -NoProfile -Command "(Get-DnsClientServerAddress -AddressFamily IPv4 | '
               'Where-Object { $_.ServerAddresses }).ServerAddresses"')
    servers = []
    for ip in re.findall(r"\d+\.\d+\.\d+\.\d+", out):
        if ip != exclude and not ip.startswith(("127.", "192.168.137.")) and ip not in servers:
            servers.append(ip)
    return servers[:3] + [s for s in FALLBACK_DNS if s not in servers]


# --------------------------------------------------------------------------- #
# HTTP portal
# --------------------------------------------------------------------------- #
PROBE_SUCCESS = {
    # path -> (status, content-type, body) expected by the OS when internet works
    "/generate_204": (204, "text/plain", b""),
    "/gen_204": (204, "text/plain", b""),
    "/hotspot-detect.html": (200, "text/html",
                             b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    "/library/test/success.html": (200, "text/html",
                                   b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    "/connecttest.txt": (200, "text/plain", b"Microsoft Connect Test"),
    "/ncsi.txt": (200, "text/plain", b"Microsoft NCSI"),
    "/success.txt": (200, "text/plain", b"success\n"),
    "/canonical.html": (200, "text/html",
                        b'<meta http-equiv="refresh" content="0;url=https://support.mozilla.org/kb/captive-portal"/>'),
}

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hiraya Wifi</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;
       justify-content:center;background:radial-gradient(circle at 20% 0%,#2b3a8f 0%,#14161b 55%);color:#e8eaed;padding:20px}}
  .card{{width:100%;max-width:380px;background:rgba(29,32,39,.92);border:1px solid #2c313c;border-radius:20px;
        padding:32px 26px;box-shadow:0 20px 60px rgba(0,0,0,.45);text-align:center}}
  .logo{{font-size:44px}} h1{{font-size:24px;margin:8px 0 4px}} .sub{{color:#9aa0a6;font-size:14px;margin-bottom:24px}}
  input{{width:100%;padding:16px;border-radius:12px;border:1px solid #333844;background:#262a33;color:#fff;
        font-size:22px;letter-spacing:6px;text-align:center;text-transform:uppercase;outline:none}}
  input:focus{{border-color:#4f8cff}}
  button{{width:100%;margin-top:14px;padding:15px;border:0;border-radius:12px;background:#4f8cff;color:#fff;
         font-size:17px;font-weight:600;cursor:pointer}}
  .msg{{margin-bottom:16px;padding:12px;border-radius:10px;font-size:14px}}
  .err{{background:rgba(255,95,87,.15);color:#ff8a84}} .ok{{background:rgba(52,199,89,.15);color:#5fdc80}}
  .timer{{font-size:40px;font-weight:700;margin:10px 0 4px;font-variant-numeric:tabular-nums}}
  .small{{color:#9aa0a6;font-size:12px;margin-top:22px}}
</style></head><body><div class="card">
<div class="logo">📶</div><h1>Hiraya Wifi</h1>
{body}
<p class="small">Powered by Hiraya Wifi Hotspot</p>
</div></body></html>"""

LOGIN_BODY = """<p class="sub">Enter your voucher code to get online</p>
{msg}
<form method="post" action="/redeem" autocomplete="off">
  <input name="code" maxlength="12" placeholder="CODE" autofocus required>
  <button type="submit">Connect</button>
</form>"""

STATUS_BODY = """<p class="sub">You're connected to the internet</p>
{msg}
<div class="timer" id="t">--</div><p class="sub">time remaining</p>
<form method="post" action="/redeem" autocomplete="off">
  <input name="code" maxlength="12" placeholder="ADD CODE">
  <button type="submit">Add time</button>
</form>
<script>
  var end = Date.now() + {remaining} * 1000;
  function tick() {{
    var s = Math.max(0, Math.round((end - Date.now()) / 1000));
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
    var p = function (n) {{ return (n < 10 ? "0" : "") + n; }};
    document.getElementById("t").textContent = (d ? d + "d " : "") + p(h) + ":" + p(m) + ":" + p(x);
    if (s <= 0) location.reload(); else setTimeout(tick, 1000);
  }}
  tick();
</script>"""


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "HirayaPortal/1.0"

    def log_message(self, *args):
        pass

    @property
    def portal(self) -> "CaptivePortal":
        return self.server.portal  # type: ignore[attr-defined]

    def _send(self, code: int, ctype: str, body: bytes, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect_to_portal(self):
        self._send(302, "text/html", b"", {"Location": f"http://{self.portal.ip}/"})

    def _page(self, mac: str | None, msg: str = "", ok: bool = False):
        msg_html = f'<div class="msg {"ok" if ok else "err"}">{html.escape(msg)}</div>' if msg else ""
        end = self.portal.store.device_end(mac) if mac else 0
        if end > time.time():
            body = STATUS_BODY.format(msg=msg_html, remaining=int(end - time.time()))
        else:
            body = LOGIN_BODY.format(msg=msg_html)
        self._send(200, "text/html", PAGE.format(body=body).encode("utf-8"))

    def _client(self):
        ip = self.client_address[0]
        mac = self.portal.arp.mac_for(ip)
        return ip, mac

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        _ip, mac = self._client()
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        path = self.path.split("?")[0]
        authorized = self.portal.store.is_authorized(mac)
        ours = host in (self.portal.ip, PORTAL_HOSTNAME, "")

        if authorized and path in PROBE_SUCCESS and not ours:
            code, ctype, body = PROBE_SUCCESS[path]
            return self._send(code, ctype, body)
        if ours:
            if path in ("/", "/index.html", "/status"):
                return self._page(mac)
            return self._redirect_to_portal()
        if authorized:
            # Stale DNS cache pointed this site at us - ask the browser to retry shortly.
            return self._send(200, "text/html",
                              b'<meta http-equiv="refresh" content="2"><p style="font-family:sans-serif">'
                              b'Connected! Loading...</p>')
        return self._redirect_to_portal()

    def do_POST(self):
        _ip, mac = self._client()
        if self.path.split("?")[0] != "/redeem":
            return self._redirect_to_portal()
        length = min(int(self.headers.get("Content-Length") or 0), 2048)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        code = (form.get("code") or [""])[0]
        if not code.strip():
            return self._page(mac)
        if not mac:
            return self._page(None, "Could not identify your device. Please reconnect to the Wi-Fi and try again.")
        ok, msg = self.portal.store.redeem(code, mac)
        if ok:
            self.portal.on_change()
        self._page(mac, msg, ok)


# --------------------------------------------------------------------------- #
# Portal service
# --------------------------------------------------------------------------- #
class CaptivePortal:
    def __init__(self, store: VoucherStore, on_change=lambda: None):
        self.store = store
        self.on_change = on_change
        self.arp = ArpCache()
        self.ip = ""
        self.upstream: list[str] = []
        self.running = False
        self._dns_sock: socket.socket | None = None
        self._http: ThreadingHTTPServer | None = None
        self._pool: ThreadPoolExecutor | None = None

    # ---- lifecycle ----
    def start(self, ip: str) -> tuple[bool, str]:
        if self.running:
            return True, "Portal already running."
        self.ip = ip
        self.upstream = detect_upstream_dns(ip)
        self._firewall(True)
        last_err = None
        for _ in range(10):  # the hotspot IP can take a few seconds to appear
            try:
                self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._dns_sock.bind((ip, 53))
                self._http = ThreadingHTTPServer((ip, 80), PortalHandler)
                break
            except OSError as e:
                last_err = e
                self._close_sockets()
                time.sleep(1)
        else:
            return False, f"Could not start captive portal on {ip}: {last_err}"
        self._http.portal = self  # type: ignore[attr-defined]
        self._http.daemon_threads = True
        self._pool = ThreadPoolExecutor(max_workers=32)
        self.running = True
        self.arp.refresh(force=True)
        threading.Thread(target=self._dns_loop, daemon=True).start()
        threading.Thread(target=self._http.serve_forever, daemon=True).start()
        return True, f"Captive portal running at http://{ip}/"

    def stop(self):
        self.running = False
        if self._http:
            try:
                self._http.shutdown()
            except Exception:
                pass
        self._close_sockets()
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    def _close_sockets(self):
        for s in (self._dns_sock,):
            try:
                s and s.close()
            except Exception:
                pass
        self._dns_sock = None
        if self._http:
            try:
                self._http.server_close()
            except Exception:
                pass
            self._http = None

    @staticmethod
    def _firewall(enable: bool):
        for name, proto, port in (("Hiraya Portal DNS", "UDP", 53), ("Hiraya Portal HTTP", "TCP", 80)):
            _run(f'netsh advfirewall firewall delete rule name="{name}"')
            if enable:
                _run(f'netsh advfirewall firewall add rule name="{name}" dir=in action=allow '
                     f'protocol={proto} localport={port} localip=192.168.137.0/24 profile=any')

    # ---- DNS ----
    def _dns_loop(self):
        sock = self._dns_sock
        while self.running and sock:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                break
            if self._pool:
                try:
                    self._pool.submit(self._handle_dns, sock, data, addr)
                except RuntimeError:
                    break

    def _handle_dns(self, sock: socket.socket, data: bytes, addr):
        try:
            qname = _read_qname(data, 12) if len(data) > 12 else ""
            if qname == PORTAL_HOSTNAME:
                resp = _hijack_answer(data, self.ip)
            elif self.store.is_authorized(self.arp.mac_for(addr[0])):
                resp = self._forward(data)
            else:
                resp = _hijack_answer(data, self.ip)
            if resp:
                sock.sendto(resp, addr)
        except Exception:
            pass

    def _forward(self, data: bytes) -> bytes | None:
        for server in self.upstream:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.5)
            try:
                s.sendto(data, (server, 53))
                resp, _ = s.recvfrom(4096)
                return _cap_ttls(resp, MAX_FORWARD_TTL)
            except OSError:
                continue
            finally:
                s.close()
        return None
