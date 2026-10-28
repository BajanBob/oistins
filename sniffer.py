"""Optional packet watcher: pings and port scans aimed at this computer.

Needs `pip install scapy` (plus Npcap on Windows) and administrator/root
rights. Without them Oistins still runs; this lamp just shows "off".
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from netinfo import is_public, local_ips


class Sniffer:
    def __init__(self, alerts, config: dict, geo) -> None:
        self.alerts, self.config, self.geo = alerts, config, geo
        self.status = "pending"
        self.detail = "Starting packet watch…"
        self.pings: dict[str, deque] = defaultdict(deque)
        self.syns: dict[str, deque] = defaultdict(deque)
        self.events: deque = deque(maxlen=40)
        self.ping_times: deque = deque()
        self.probe_times: deque = deque()
        self.local = local_ips()
        self._seen_ping: set[str] = set()

    def start(self) -> None:
        try:
            import scapy.all  # noqa: F401
        except ImportError:
            self.status = "off"
            self.detail = ("Optional: install scapy (pip install scapy; Npcap on Windows) and run "
                           "Oistins as administrator to catch pings and port scans.")
            return
        threading.Thread(target=self._run, daemon=True, name="sniffer").start()

    def _run(self) -> None:
        from scapy.all import sniff
        try:
            self.status, self.detail = "ok", "Watching for pings and port scans."
            sniff(filter="icmp or (tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)",
                  prn=self._handle, store=False)
        except PermissionError:
            self.status, self.detail = "off", "Run Oistins as administrator/root to watch packets."
        except Exception as e:  # noqa: BLE001
            self.status, self.detail = "off", f"Packet watch unavailable: {e}"

    def _where(self, ip: str) -> str:
        g = self.geo.get(ip)
        return f"{ip} ({g.get('country')})" if g.get("country") else ip

    def _handle(self, pkt) -> None:
        from scapy.all import ICMP, IP, TCP
        if IP not in pkt:
            return
        src, dst, now = pkt[IP].src, pkt[IP].dst, time.time()
        if dst not in self.local or src in self.local:
            return
        if ICMP in pkt and pkt[ICMP].type == 8:
            self.ping_times.append(now)
            dq = self.pings[src]
            dq.append(now)
            while dq and now - dq[0] > 60:
                dq.popleft()
            self.events.append({"t": now, "kind": "ping", "ip": src})
            if len(dq) >= self.config["ping_threshold"]:
                self.alerts.raise_(f"pingflood:{src}", "warn", "Pings",
                                   f"Ping flood from {self._where(src)}",
                                   f"{len(dq)} echo requests in the last minute.")
            elif is_public(src) and src not in self._seen_ping:
                self._seen_ping.add(src)
                self.alerts.raise_(f"ping:{src}", "info", "Pings",
                                   f"Ping from internet host {self._where(src)}")
        elif TCP in pkt:
            port = int(pkt[TCP].dport)
            self.probe_times.append(now)
            dq = self.syns[src]
            dq.append((now, port))
            while dq and now - dq[0][0] > 60:
                dq.popleft()
            ports = sorted({p for _, p in dq})
            if len(ports) >= self.config["scan_threshold"]:
                self.events.append({"t": now, "kind": "scan", "ip": src})
                self.alerts.raise_(f"scan:{src}", "crit", "Intrusion",
                                   f"Port scan from {self._where(src)}",
                                   f"{len(ports)} ports probed in 60 s: {', '.join(map(str, ports[:20]))}…")

    def snapshot(self) -> dict:
        now = time.time()
        for dq in (self.ping_times, self.probe_times):
            while dq and now - dq[0] > 60:
                dq.popleft()
        if int(now) % 30 == 0:
            self.local = local_ips()
        return {"status": self.status, "detail": self.detail,
                "pings_per_min": len(self.ping_times), "syns_per_min": len(self.probe_times),
                "events": list(self.events)[-15:]}
