"""Individual network checks: connections/ports, traceroute, TLS, DNS, HTTP injection, speed."""

from __future__ import annotations

import os
import random
import re
import shutil
import socket
import ssl
import statistics
import string
import time
import urllib.error
import urllib.request

import psutil

from netinfo import IP_RE, OS, UA, is_public, run

# ---------------------------------------------------------------- ports
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 69: "TFTP", 110: "POP3", 135: "Windows RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS/SMB", 445: "SMB file sharing",
    1433: "MS SQL", 1900: "UPnP/SSDP", 2323: "Telnet (alt)", 3306: "MySQL",
    3389: "Remote Desktop", 4444: "Known backdoor port", 5432: "PostgreSQL",
    5555: "Android ADB", 5900: "VNC remote desktop", 5985: "WinRM", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 31337: "Known backdoor port",
}

_names: dict[int, str] = {}


def _pname(pid: int | None) -> str:
    if not pid:
        return "system"
    if pid not in _names:
        try:
            _names[pid] = psutil.Process(pid).name()
        except (psutil.Error, OSError):
            return "?"
    return _names[pid]


def _raw_connections():
    try:
        return [(c, c.pid) for c in psutil.net_connections(kind="inet")]
    except (psutil.AccessDenied, PermissionError):
        # macOS without admin: fall back to the processes we're allowed to see
        out = []
        for p in psutil.process_iter():
            try:
                fn = getattr(p, "net_connections", None) or p.connections
                out += [(c, p.pid) for c in fn(kind="inet")]
            except (psutil.Error, OSError):
                continue
        return out


def connections(geo) -> tuple[list[dict], list[dict]]:
    """(active connections, listening ports)."""
    raw = _raw_connections()
    listening: dict[tuple, dict] = {}
    tcp_listen: set[int] = set()
    for c, pid in raw:
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        if (proto == "TCP" and c.status == psutil.CONN_LISTEN) or (proto == "UDP" and not c.raddr):
            ip, port = c.laddr.ip, c.laddr.port
            exposed = not (ip.startswith("127.") or ip in ("::1", "localhost"))
            listening[(proto, ip, port)] = {
                "proto": proto, "ip": ip, "port": port, "pid": pid, "proc": _pname(pid),
                "exposed": exposed, "risk": RISKY_PORTS.get(port)}
            if proto == "TCP":
                tcp_listen.add(port)
    conns = []
    for c, pid in raw:
        if not c.raddr or not c.raddr.ip:
            continue
        rip = c.raddr.ip.removeprefix("::ffff:")
        if rip.startswith("127.") or rip == "::1":
            continue
        g = geo.get(rip)
        conns.append({
            "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "dir": "in" if c.laddr.port in tcp_listen else "out",
            "lport": c.laddr.port, "ip": rip, "rport": c.raddr.port,
            "status": c.status if c.status != "NONE" else "", "pid": pid, "proc": _pname(pid),
            "public": is_public(rip), "cc": g.get("cc", ""), "country": g.get("country", ""),
            "org": g.get("org", ""), "risk": RISKY_PORTS.get(c.laddr.port) if c.laddr.port in tcp_listen else None,
        })
    conns.sort(key=lambda x: (x["dir"] != "in", not x["public"], x["ip"]))
    return conns, sorted(listening.values(), key=lambda x: (not x["exposed"], x["port"]))


# ---------------------------------------------------------------- traceroute
def traceroute(target: str, max_hops: int = 20) -> list[dict] | None:
    if OS == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", target]
    elif shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), target]
    elif shutil.which("tracepath"):
        cmd = ["tracepath", "-n", "-m", str(max_hops), target]
    else:
        return None
    hops: list[dict] = []
    for line in run(cmd, timeout=max_hops * 4).splitlines():
        m = re.match(r"\s*(\d+)\??:?\s+(.*)", line)
        if not m:
            continue
        ttl, rest = int(m.group(1)), m.group(2)
        ip, rtt = IP_RE.search(rest), re.search(r"<?([\d.]+)\s*ms", rest)
        if hops and hops[-1]["ttl"] == ttl:  # tracepath prints a hop more than once
            if not hops[-1]["ip"] and ip:
                hops[-1]["ip"] = ip.group(1)
            continue
        hops.append({"ttl": ttl, "ip": ip.group(1) if ip else None,
                     "rtt": float(rtt.group(1)) if rtt else None})
    return hops


# ---------------------------------------------------------------- TLS (man-in-the-middle)
TLS_HOSTS = ["www.google.com", "www.cloudflare.com", "github.com", "www.wikipedia.org"]
PUBLIC_CAS = ["google trust services", "digicert", "let's encrypt", "sectigo", "globalsign",
              "amazon", "microsoft", "entrust", "godaddy", "comodo", "usertrust", "cloudflare",
              "certainly", "starfield", "identrust", "buypass", "ssl.com", "harica", "actalis",
              "quovadis", "certum", "zerossl", "telia", "geotrust", "thawte", "rapidssl", "apple"]
INTERCEPTORS = ["avast", "avg", "kaspersky", "eset", "bitdefender", "zscaler", "fortinet",
                "fortigate", "palo alto", "sophos", "netskope", "mitmproxy", "charles", "fiddler",
                "portswigger", "burp", "blue coat", "umbrella", "norton", "mcafee", "forcepoint",
                "barracuda", "watchguard", "sonicwall", "check point", "untangle", "cisco"]


def tls_check(host: str) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                issuer = dict(x[0] for x in t.getpeercert()["issuer"])
        org = issuer.get("organizationName") or issuer.get("commonName") or "?"
        low = org.lower()
        kind = ("interceptor" if any(k in low for k in INTERCEPTORS)
                else "public" if any(k in low for k in PUBLIC_CAS) else "unknown")
        return {"host": host, "verified": True, "issuer": org, "kind": kind}
    except ssl.SSLCertVerificationError as e:
        return {"host": host, "verified": False, "error": e.verify_message or str(e)}
    except OSError as e:
        return {"host": host, "verified": None, "error": str(e)}


# ---------------------------------------------------------------- DNS
DNS_EXPECT = {"one.one.one.one": {"1.1.1.1", "1.0.0.1"}, "dns.google": {"8.8.8.8", "8.8.4.4"}}


def _resolve(name: str) -> set[str]:
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(name, 443, socket.AF_INET)}
    except OSError:
        return set()


def dns_check() -> dict:
    wrong = {}
    failed = []
    for name, expect in DNS_EXPECT.items():
        got = _resolve(name)
        if not got:
            failed.append(name)
        elif not got & expect:
            wrong[name] = sorted(got)
    fake = "".join(random.choices(string.ascii_lowercase + string.digits, k=26)) + ".com"
    nx = sorted(_resolve(fake))
    return {"wrong": wrong, "failed": failed, "nxdomain_hijack": nx}


# ---------------------------------------------------------------- HTTP injection / captive portal
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


PROBES = [("http://connectivitycheck.gstatic.com/generate_204", 204, b""),
          ("http://detectportal.firefox.com/success.txt", 200, b"success")]


def injection_check() -> dict:
    opener = urllib.request.build_opener(_NoRedirect)
    tampered, unreachable = [], []
    for url, code, body in PROBES:
        try:
            r = opener.open(urllib.request.Request(url, headers=UA), timeout=8)
            status, data = r.status, r.read(4096).strip()
        except urllib.error.HTTPError as e:
            status, data = e.code, b""
        except OSError:
            unreachable.append(url)
            continue
        if status != code or (body and not data.startswith(body)) or (not body and data):
            tampered.append(f"{url} → HTTP {status}, {len(data)} bytes")
    return {"tampered": tampered, "unreachable": unreachable}


# ---------------------------------------------------------------- speed
CF = "https://speed.cloudflare.com"


def latency(host: str = "1.1.1.1", port: int = 443, n: int = 6) -> dict:
    times, lost = [], 0
    for _ in range(n):
        t = time.perf_counter()
        try:
            socket.create_connection((host, port), timeout=3).close()
            times.append((time.perf_counter() - t) * 1000)
        except OSError:
            lost += 1
        time.sleep(0.15)
    if not times:
        return {"latency": None, "jitter": None, "loss": 100}
    jitter = statistics.mean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else 0
    return {"latency": round(statistics.median(times), 1), "jitter": round(jitter, 1),
            "loss": round(lost * 100 / n)}


def download_mbps(max_bytes: int = 50_000_000, max_s: float = 10) -> float | None:
    try:
        req = urllib.request.Request(f"{CF}/__down?bytes={max_bytes}", headers=UA)
        t, total = time.perf_counter(), 0
        with urllib.request.urlopen(req, timeout=15) as r:
            while time.perf_counter() - t < max_s:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
        return round(total * 8 / (time.perf_counter() - t) / 1e6, 1)
    except OSError:
        return None


def upload_mbps(size: int = 8_000_000) -> float | None:
    try:
        data = os.urandom(size)
        req = urllib.request.Request(f"{CF}/__up", data=data, headers=UA, method="POST")
        t = time.perf_counter()
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        return round(size * 8 / (time.perf_counter() - t) / 1e6, 1)
    except OSError:
        return None
