"""Simulated data so you can try the panel (python oistins.py --demo)."""

from __future__ import annotations

import math
import random
import tempfile
import threading
import time
from collections import deque
from pathlib import Path

from store import AlertBook, Store

HOSTS = [
    ("142.250.80.46", "US", "United States", "Google LLC", "chrome", 443),
    ("104.16.132.229", "US", "United States", "Cloudflare", "chrome", 443),
    ("151.101.1.140", "US", "United States", "Fastly", "firefox", 443),
    ("52.97.146.162", "IE", "Ireland", "Microsoft", "OUTLOOK", 443),
    ("31.13.71.36", "GB", "United Kingdom", "Meta", "WhatsApp", 443),
    ("185.199.108.133", "NL", "Netherlands", "GitHub", "git", 443),
    ("190.213.4.10", "BB", "Barbados", "Flow Barbados", "svchost", 53),
    ("162.159.135.234", "DE", "Germany", "Discord", "Discord", 443),
    ("203.104.153.1", "JP", "Japan", "NTT", "steam", 27036),
    ("17.253.144.10", "US", "United States", "Apple", "iCloud", 443),
]
SCANNER = ("45.155.205.77", "RU", "Russia", "Unknown hosting")


class DemoEngine:
    def __init__(self) -> None:
        self.store = Store(Path(tempfile.mkdtemp(prefix="oistins-demo-")))
        self.alerts = AlertBook(self.store)
        self.wake_speed, self.wake_trace, self.wake_sec = (threading.Event() for _ in range(3))
        self.history: deque = deque(maxlen=120)
        self.t0 = time.time()
        self.trusted: set[int] = set()

    def start(self) -> None:
        a = self.alerts
        a.raise_("scan:demo", "crit", "Intrusion", f"Port scan from {SCANNER[0]} ({SCANNER[2]})",
                 "22 ports probed in 60 s: 21, 22, 23, 80, 135, 139, 443, 445, 3389, 5900…")
        a.raise_("newport:TCP/3389", "crit", "Ports", "New open port TCP 3389 (svchost.exe)",
                 "Listening on 0.0.0.0 — Remote Desktop. Opened 02:14 during quiet hours.")
        a.raise_("dns:nx", "warn", "DNS", "DNS redirection detected",
                 "Made-up domains resolve to 92.242.132.24 (ISP ad redirect or hijack).")
        a.raise_("ping:demo", "info", "Pings", "Ping from internet host 89.248.165.12 (Netherlands)")
        a.raise_("pubip:demo", "info", "Network", "Your public IP changed",
                 "190.213.40.11 → 190.213.40.87 (normal after a router restart or VPN switch).")
        threading.Thread(target=self._tick, daemon=True).start()

    def _tick(self) -> None:
        while True:
            t = time.time() - self.t0
            rx = max(0.05, 18 + 14 * math.sin(t / 7) + random.uniform(-4, 6))
            tx = max(0.02, 2.5 + 1.8 * math.sin(t / 5 + 1) + random.uniform(-0.5, 0.8))
            self.history.append((round(rx, 2), round(tx, 2)))
            if self.wake_sec.is_set() or self.wake_trace.is_set() or self.wake_speed.is_set():
                self.wake_sec.clear(); self.wake_trace.clear(); self.wake_speed.clear()
            time.sleep(1)

    def snapshot(self) -> dict:
        rx, tx = self.history[-1] if self.history else (0, 0)
        conns = []
        for i, (ip, cc, country, org, proc, port) in enumerate(HOSTS):
            conns.append({"proto": "TCP", "dir": "out", "lport": 50100 + i, "ip": ip, "rport": port,
                          "status": "ESTABLISHED", "proc": proc, "public": True, "cc": cc,
                          "country": country, "org": org, "risk": None})
        conns.insert(0, {"proto": "TCP", "dir": "in", "lport": 3389, "ip": SCANNER[0], "rport": 51544,
                         "status": "SYN_RECV", "proc": "svchost", "public": True, "cc": SCANNER[1],
                         "country": SCANNER[2], "org": SCANNER[3], "risk": "Remote Desktop"})
        conns.append({"proto": "TCP", "dir": "in", "lport": 445, "ip": "192.168.1.23", "rport": 49822,
                      "status": "ESTABLISHED", "proc": "System", "public": False, "cc": "LAN",
                      "country": "Local network", "org": "", "risk": "SMB file sharing"})
        listening = [
            {"proto": "TCP", "ip": "0.0.0.0", "port": 3389, "proc": "svchost", "exposed": True,
             "risk": "Remote Desktop", "new": True, "trusted": 3389 in self.trusted},
            {"proto": "TCP", "ip": "0.0.0.0", "port": 445, "proc": "System", "exposed": True,
             "risk": "SMB file sharing", "new": False, "trusted": 445 in self.trusted},
            {"proto": "TCP", "ip": "0.0.0.0", "port": 7680, "proc": "svchost", "exposed": True,
             "risk": None, "new": False, "trusted": False},
            {"proto": "UDP", "ip": "0.0.0.0", "port": 5353, "proc": "chrome", "exposed": True,
             "risk": None, "new": False, "trusted": False},
            {"proto": "TCP", "ip": "127.0.0.1", "port": 8787, "proc": "oistins", "exposed": False,
             "risk": None, "new": False, "trusted": False},
        ]

        def hop(ttl, ip, rtt, cc, country, org):
            return {"ttl": ttl, "ip": ip, "rtt": rtt, "cc": cc, "country": country, "org": org}
        routes = {
            "1.1.1.1": {"at": time.time() - 120, "hops": [
                hop(1, "192.168.1.1", 1.2, "LAN", "Local network", ""),
                hop(2, "190.213.0.1", 6.8, "BB", "Barbados", "Flow Barbados"),
                hop(3, "190.213.255.5", 9.1, "BB", "Barbados", "Flow Barbados"),
                hop(4, None, None, "", "", ""),
                hop(5, "63.245.5.18", 31.4, "US", "United States", "Liberty Latin America"),
                hop(6, "1.1.1.1", 33.0, "US", "United States", "Cloudflare")]},
            "8.8.8.8": {"at": time.time() - 120, "hops": [
                hop(1, "192.168.1.1", 1.1, "LAN", "Local network", ""),
                hop(2, "190.213.0.1", 7.2, "BB", "Barbados", "Flow Barbados"),
                hop(3, "200.0.53.9", 14.0, "TT", "Trinidad and Tobago", "TSTT"),
                hop(4, "72.14.219.1", 38.5, "US", "United States", "Google LLC"),
                hop(5, "8.8.8.8", 39.8, "US", "United States", "Google LLC")]},
        }
        checks = {
            "arp": {"status": "ok", "detail": "Router 192.168.1.1 = 3c:84:6a:12:9e:01, unchanged."},
            "tls": {"status": "ok", "detail": "4 sites verified with genuine public certificates."},
            "dns": {"status": "warn", "detail": "Made-up domains resolve to 92.242.132.24."},
            "injection": {"status": "ok", "detail": "Unencrypted test pages arrived unmodified."},
            "ports": {"status": "crit", "detail": "5 open (4 reachable from network), 1 new since baseline."},
            "vuln": {"status": "warn", "detail": "Remote Desktop :3389, SMB file sharing :445"},
            "routing": {"status": "ok", "detail": "2 paths match the learned routes."},
            "intrusion": {"status": "crit", "detail": "Watching for pings and port scans."},
            "cellular": {"status": "off", "detail": "A computer can't read cell-tower signals. "
                         "Use EFF Rayhunter or SnoopSnitch on a rooted Android phone."},
        }
        alerts = self.alerts.snapshot()
        if not any(a["key"] == "scan:demo" and not a["acked"] for a in alerts):
            checks["intrusion"]["status"] = "ok"
        return {
            "network": {"gateway": "192.168.1.1", "gateway_mac": "3c:84:6a:12:9e:01", "iface": "Wi-Fi",
                        "public_ip": "190.213.40.87",
                        "public_geo": {"cc": "BB", "country": "Barbados", "org": "Flow Barbados"},
                        "interfaces": [{"name": "Wi-Fi", "ipv4": ["192.168.1.34"], "kind": "wifi"}]},
            "throughput": {"rx": rx, "tx": tx},
            "speed": {"download": 94.6, "upload": 18.3, "latency": 32.4, "jitter": 2.1, "loss": 0,
                      "at": time.time() - 300, "running": False},
            "connections": conns, "listening": listening, "routes": routes, "checks": checks,
            "sniffer": {"status": "ok", "pings_per_min": random.randint(0, 3),
                        "syns_per_min": random.randint(18, 30), "events": []},
            "history": list(self.history), "alerts": alerts, "alarm": self.alerts.alarm(),
            "quiet_hours": False,
            "counts": {"in": 2, "out": len(HOSTS), "countries": 8},
            "config": {"trusted_ports": sorted(self.trusted), "trusted_countries": [],
                       "quiet_hours": [0, 6], "geo_mode": "demo"},
            "time": time.time(), "demo": True,
        }

    def ack(self, key):
        self.alerts.ack(key)

    def trust_port(self, port):
        self.trusted.add(port)
        for a in self.alerts.snapshot():
            if a["key"].endswith(f"/{port}"):
                self.alerts.ack(a["key"])

    def rebaseline(self):
        self.alerts.ack(None)
