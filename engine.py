"""Runs all monitors in background threads and keeps the dashboard state."""

from __future__ import annotations

import copy
import threading
import time
from collections import deque
from datetime import datetime

import psutil

import checks
from geo import Geo
from netinfo import arp_table, default_gateway, interfaces, is_public, public_ip
from sniffer import Sniffer
from store import AlertBook, Store

LAMPS = ["arp", "tls", "dns", "injection", "ports", "vuln", "routing", "intrusion", "cellular"]


class Engine:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.cfg = store.config
        self.alerts = AlertBook(store)
        self.geo = Geo(self.cfg["geo_mode"], self.cfg["geo_db"])
        self.sniffer = Sniffer(self.alerts, self.cfg, self.geo)
        self.lock = threading.Lock()
        self.wake_speed, self.wake_trace, self.wake_sec = (threading.Event() for _ in range(3))
        self.history: deque = deque(maxlen=120)
        self.net_id = "unknown"
        self.state: dict = {
            "network": {}, "throughput": {"rx": 0, "tx": 0}, "speed": {"running": False},
            "connections": [], "listening": [], "routes": {},
            "checks": {k: {"status": "pending", "detail": "Waiting for first check…"} for k in LAMPS},
        }

    # ------------------------------------------------------------ plumbing
    def set_check(self, name: str, status: str, detail: str) -> None:
        with self.lock:
            self.state["checks"][name] = {"status": status, "detail": detail, "at": time.time()}

    def _loop(self, fn, interval, wake: threading.Event | None = None) -> None:
        def run():
            while True:
                try:
                    fn()
                except Exception as e:  # noqa: BLE001 - never let a monitor die
                    print(f"[oistins] {fn.__name__}: {e}")
                secs = interval() if callable(interval) else interval
                if wake:
                    wake.wait(secs)
                    wake.clear()
                else:
                    time.sleep(secs)
        threading.Thread(target=run, daemon=True, name=fn.__name__).start()

    def start(self) -> None:
        self._loop(self.live, 1)
        self._loop(self.scan_connections, 3)
        self._loop(self.geo_and_routes, 2)
        self._loop(self.security, lambda: self.cfg["security_interval_s"], self.wake_sec)
        self._loop(self.trace, lambda: self.cfg["trace_interval_min"] * 60, self.wake_trace)
        self._loop(self.speedtest, lambda: self.cfg["speed_interval_min"] * 60, self.wake_speed)
        self.sniffer.start()

    def quiet_hours(self) -> bool:
        a, b = self.cfg["quiet_hours"]
        h = datetime.now().hour
        return a <= h < b if a <= b else h >= a or h < b

    def nb(self) -> dict:
        return self.store.net_baseline(self.net_id)

    # ------------------------------------------------------------ live throughput
    _last_io = None

    def live(self) -> None:
        io, now = psutil.net_io_counters(), time.time()
        if self._last_io:
            (pio, pt) = self._last_io
            dt = max(now - pt, 0.001)
            rx = (io.bytes_recv - pio.bytes_recv) * 8 / dt / 1e6
            tx = (io.bytes_sent - pio.bytes_sent) * 8 / dt / 1e6
            self.history.append((round(rx, 2), round(tx, 2)))
            with self.lock:
                self.state["throughput"] = {"rx": round(rx, 2), "tx": round(tx, 2)}
        self._last_io = (io, now)

    # ------------------------------------------------------------ connections & ports
    def scan_connections(self) -> None:
        conns, listening = checks.connections(self.geo)
        trusted = set(self.cfg["trusted_ports"])
        quiet = self.quiet_hours()
        nb = self.nb()
        keys = sorted({f"{p['proto']}/{p['port']}" for p in listening})
        if "ports" not in nb:  # first run on this network: learn what's normal
            nb["ports"] = keys
            nb["learned_at"] = time.time()
            self.store.save()
        known = set(nb["ports"])

        new_exposed = 0
        for p in listening:
            key = f"{p['proto']}/{p['port']}"
            p["new"] = key not in known
            p["trusted"] = p["port"] in trusted
            if not p["new"] or p["trusted"]:
                continue
            if p["exposed"]:
                new_exposed += 1
            level = ("crit" if p["exposed"] and (p["risk"] or quiet)
                     else "warn" if p["exposed"] else "info")
            when = datetime.now().strftime("%H:%M")
            self.alerts.raise_(
                f"newport:{key}", level, "Ports",
                f"New open port {p['proto']} {p['port']} ({p['proc']})",
                f"Listening on {p['ip']}{' — ' + p['risk'] if p['risk'] else ''}. "
                f"Opened {when}{' during quiet hours' if quiet else ''}. "
                "Trust it if you expected this.")

        vulns = [p for p in listening if p["exposed"] and p["risk"] and not p["trusted"]]
        for p in vulns:
            self.alerts.raise_(f"vuln:{p['port']}", "warn", "Ports",
                               f"Vulnerable service reachable: {p['risk']} (port {p['port']})",
                               f"{p['proc']} listens on {p['ip']}. Close it or firewall it if not needed.")
        exposed = sum(p["exposed"] for p in listening)
        self.set_check("ports", "crit" if new_exposed and quiet else "warn" if new_exposed else "ok",
                       f"{len(listening)} open ({exposed} reachable from network), "
                       f"{new_exposed} new since baseline.")
        self.set_check("vuln", "warn" if vulns else "ok",
                       ", ".join(f"{p['risk']} :{p['port']}" for p in vulns) or "No risky services exposed.")

        tc = set(c.upper() for c in self.cfg["trusted_countries"])
        for c in conns:
            if not c["public"]:
                continue
            where = f"{c['ip']} ({c['country'] or '…'})"
            if c["dir"] == "in" and c["risk"]:
                self.alerts.raise_(f"inrisk:{c['ip']}:{c['lport']}", "crit", "Intrusion",
                                   f"Inbound {c['risk']} connection from {where}",
                                   f"Remote port {c['rport']} → your port {c['lport']} ({c['proc']}).")
            elif c["dir"] == "in" and quiet:
                self.alerts.raise_(f"innight:{c['ip']}:{c['lport']}", "warn", "Intrusion",
                                   f"Inbound connection during quiet hours from {where}",
                                   f"To port {c['lport']} ({c['proc']}).")
            if tc and c["cc"] and c["cc"] not in tc:
                self.alerts.raise_(f"cc:{c['ip']}", "warn", "Countries",
                                   f"{'Incoming' if c['dir'] == 'in' else 'Outgoing'} traffic with "
                                   f"{c['country']}", f"{c['ip']} · {c['org']} · {c['proc']}")
        with self.lock:
            self.state["connections"] = conns[:500]
            self.state["listening"] = listening

    # ------------------------------------------------------------ security checks
    def security(self) -> None:
        gw, iface = default_gateway()
        new_id = f"{gw}|{iface}" if gw else "offline"
        if new_id != self.net_id and self.net_id != "unknown":
            self.alerts.raise_(f"netchange:{new_id}", "info", "Network",
                               "Network changed", f"Now via gateway {gw} on {iface}.")
            self.wake_trace.set()
        self.net_id = new_id
        ifs = interfaces()
        pip = public_ip()
        nb = self.nb()
        if pip and nb.get("public_ip") and pip != nb["public_ip"]:
            self.alerts.raise_(f"pubip:{pip}", "info", "Network", "Your public IP changed",
                               f"{nb['public_ip']} → {pip} (normal after a router restart or VPN switch).")
        if pip:
            nb["public_ip"] = pip
            self.geo.get(pip)
        with self.lock:
            self.state["network"] = {"gateway": gw, "iface": iface, "public_ip": pip,
                                     "interfaces": ifs, "net_id": new_id,
                                     "learned_at": nb.get("learned_at")}
        self._check_arp(gw, nb)
        self._check_tls(nb)
        self._check_dns()
        self._check_injection()
        self._check_cellular(ifs)
        self.store.save()

    def _check_arp(self, gw, nb) -> None:
        if not gw:
            return self.set_check("arp", "off", "No default gateway (offline?).")
        table = arp_table()
        mac = table.get(gw)
        if not mac:
            return self.set_check("arp", "pending", f"Router {gw} not in ARP table yet.")
        with self.lock:
            self.state["network"]["gateway_mac"] = mac
        old = nb.setdefault("gw_mac", mac)
        twins = [ip for ip, m in table.items() if m == mac and ip != gw]
        if old != mac:
            self.alerts.raise_(f"arpmac:{mac}", "crit", "MITM",
                               "Router hardware address changed: possible ARP spoofing",
                               f"{gw} was {old}, now {mac}. If you didn't replace your router, "
                               "someone on this network may be intercepting traffic.")
            self.set_check("arp", "crit", f"Router {gw}: {old} → {mac}")
        elif twins:
            self.alerts.raise_(f"arptwin:{mac}", "crit", "MITM",
                               "Another device claims your router's address",
                               f"{', '.join(twins)} share MAC {mac} with router {gw}.")
            self.set_check("arp", "crit", f"Duplicate MAC on {', '.join(twins)}")
        else:
            self.set_check("arp", "ok", f"Router {gw} = {mac}, unchanged.")

    def _check_tls(self, nb) -> None:
        res = [checks.tls_check(h) for h in checks.TLS_HOSTS]
        seen = nb.setdefault("tls", {})
        bad, inspect, changed, reached = [], [], [], 0
        for r in res:
            if r["verified"] is None:
                continue
            reached += 1
            if r["verified"] is False:
                bad.append(f"{r['host']}: {r['error']}")
            elif r["kind"] == "interceptor":
                inspect.append(f"{r['host']} by {r['issuer']}")
            elif r["kind"] == "unknown":
                inspect.append(f"{r['host']} by unknown issuer {r['issuer']}")
            if r.get("issuer"):
                prev = seen.setdefault(r["host"], r["issuer"])
                if prev != r["issuer"] and r["kind"] != "public":
                    changed.append(f"{r['host']}: {prev} → {r['issuer']}")
                seen[r["host"]] = r["issuer"] if r["kind"] == "public" else prev
        if bad:
            self.alerts.raise_("tls:bad", "crit", "MITM", "Untrusted security certificates",
                               "; ".join(bad) + ". Something may be intercepting encrypted traffic.")
            self.set_check("tls", "crit", "; ".join(bad))
        elif inspect or changed:
            self.alerts.raise_("tls:inspect", "warn", "MITM", "Encrypted traffic is being inspected",
                               "; ".join(inspect + changed) + ". Often antivirus or a work network; "
                               "if not, treat as man-in-the-middle.")
            self.set_check("tls", "warn", "; ".join(inspect + changed))
        elif reached:
            self.set_check("tls", "ok", f"{reached} sites verified with genuine public certificates.")
        else:
            self.set_check("tls", "off", "Couldn't reach test sites.")

    def _check_dns(self) -> None:
        r = checks.dns_check()
        if r["wrong"]:
            d = "; ".join(f"{k} → {', '.join(v)}" for k, v in r["wrong"].items())
            self.alerts.raise_("dns:wrong", "crit", "DNS", "DNS answers are being altered", d)
            self.set_check("dns", "crit", d)
        elif r["nxdomain_hijack"]:
            d = f"Made-up domains resolve to {', '.join(r['nxdomain_hijack'])} (ISP ad redirect or hijack)."
            self.alerts.raise_("dns:nx", "warn", "DNS", "DNS redirection detected", d)
            self.set_check("dns", "warn", d)
        elif len(r["failed"]) == len(checks.DNS_EXPECT):
            self.set_check("dns", "off", "DNS lookups failing (offline?).")
        else:
            self.set_check("dns", "ok", "Known names resolve correctly; no redirection.")

    def _check_injection(self) -> None:
        r = checks.injection_check()
        if r["tampered"]:
            d = "; ".join(r["tampered"])
            self.alerts.raise_("inject", "warn", "Injection",
                               "Web traffic is being modified or redirected",
                               d + ". Captive Wi-Fi login page, ISP injection or an attacker.")
            self.set_check("injection", "warn", d)
        elif len(r["unreachable"]) == len(checks.PROBES):
            self.set_check("injection", "off", "Test pages unreachable.")
        else:
            self.set_check("injection", "ok", "Unencrypted test pages arrived unmodified.")

    def _check_cellular(self, ifs) -> None:
        cell = [i["name"] for i in ifs if i["kind"] == "cellular"]
        msg = ("A computer can't read cell-tower signals, so fake towers / IMSI catchers can't be "
               "detected here. Use a dedicated detector such as EFF Rayhunter, or SnoopSnitch "
               "on a rooted Android phone.")
        self.set_check("cellular", "off",
                       (f"Cellular link {', '.join(cell)} in use. " if cell else "") + msg)

    # ------------------------------------------------------------ routes
    def trace(self) -> None:
        routes = {}
        for target in self.cfg["trace_targets"]:
            hops = checks.traceroute(target)
            if hops is None:
                self.set_check("routing", "off", "Install traceroute (Linux: sudo apt install traceroute).")
                return
            routes[target] = {"hops": hops, "at": time.time()}
            for h in hops:
                self.geo.get(h["ip"])
        with self.lock:
            self.state["routes"] = routes
        self._analyze_routes()

    def _analyze_routes(self) -> None:
        with self.lock:
            routes = copy.deepcopy(self.state["routes"])
        if not routes:
            return
        base = self.nb().setdefault("routes", {})
        issues, level = [], "ok"
        for target, r in routes.items():
            hops = [h for h in r["hops"] if h["ip"]]
            if not hops:
                continue
            ccs = [self.geo.get(h["ip"]).get("cc") for h in hops if is_public(h["ip"])]
            if any(c in (None, "") for c in ccs):
                continue  # wait until every hop has a country
            b = base.get(target)
            first = hops[0]["ip"]
            cset = sorted(set(ccs))
            if not b:
                base[target] = {"first": first, "countries": cset, "len": len(r["hops"])}
                self.store.save()
                continue
            if first != b["first"]:
                level = "crit"
                issues.append(f"{target}: first hop {b['first']} → {first}")
                self.alerts.raise_(f"route1:{target}:{first}", "crit", "Routing",
                                   "Traffic is leaving through a different first hop",
                                   f"Path to {target} now starts at {first} instead of {b['first']}. "
                                   "Possible rogue router or diversion.")
            new = [c for c in cset if c not in b["countries"]]
            if new:
                level = "crit" if level == "crit" else "warn"
                issues.append(f"{target}: new countries {', '.join(new)}")
                self.alerts.raise_(f"routecc:{target}:{','.join(new)}", "warn", "Routing",
                                   f"Traffic to {target} now passes through {', '.join(new)}",
                                   f"Usual path countries: {', '.join(b['countries']) or 'none'}.")
            if abs(len(r["hops"]) - b["len"]) > 5:
                issues.append(f"{target}: {b['len']} → {len(r['hops'])} hops")
                self.alerts.raise_(f"routelen:{target}:{len(r['hops'])}", "info", "Routing",
                                   f"Route to {target} changed length",
                                   f"{b['len']} → {len(r['hops'])} hops.")
        self.set_check("routing", level,
                       "; ".join(issues) or f"{len(routes)} paths match the learned routes.")

    def geo_and_routes(self) -> None:
        self.geo.resolve_pending()
        if self.state["checks"]["routing"]["status"] == "pending" or int(time.time()) % 20 < 2:
            self._analyze_routes()

    # ------------------------------------------------------------ speed
    def speedtest(self) -> None:
        with self.lock:
            self.state["speed"]["running"] = True
        lat = checks.latency()
        down = checks.download_mbps()
        up = checks.upload_mbps()
        with self.lock:
            self.state["speed"] = {**lat, "download": down, "upload": up,
                                   "at": time.time(), "running": False}

    # ------------------------------------------------------------ dashboard API
    def snapshot(self) -> dict:
        with self.lock:
            s = copy.deepcopy(self.state)
        for r in s["routes"].values():
            for h in r["hops"]:
                g = self.geo.get(h["ip"]) if h["ip"] else {}
                h.update(cc=g.get("cc", ""), country=g.get("country", ""), org=g.get("org", ""))
        pip = s["network"].get("public_ip")
        s["network"]["public_geo"] = self.geo.get(pip) if pip else {}
        sn = self.sniffer.snapshot()
        s["sniffer"] = sn
        s["checks"]["intrusion"] = {"status": sn["status"], "detail": sn["detail"]}
        if any(a["category"] == "Intrusion" and not a["acked"] and a["level"] == "crit"
               for a in self.alerts.snapshot()):
            s["checks"]["intrusion"]["status"] = "crit"
        s["history"] = list(self.history)
        s["alerts"] = self.alerts.snapshot()
        s["alarm"] = self.alerts.alarm()
        s["quiet_hours"] = self.quiet_hours()
        s["counts"] = {
            "in": sum(c["dir"] == "in" for c in s["connections"]),
            "out": sum(c["dir"] == "out" for c in s["connections"]),
            "countries": len({c["cc"] for c in s["connections"] if c["cc"] and c["cc"] != "LAN"}),
        }
        s["config"] = {k: self.cfg[k] for k in ("trusted_ports", "trusted_countries", "quiet_hours", "geo_mode")}
        s["time"] = time.time()
        return s

    def ack(self, key: str | None) -> None:
        self.alerts.ack(key)

    def trust_port(self, port: int) -> None:
        if port not in self.cfg["trusted_ports"]:
            self.cfg["trusted_ports"].append(port)
        for a in self.alerts.snapshot():
            if a["key"].endswith(f"/{port}") or a["key"] == f"vuln:{port}":
                self.alerts.ack(a["key"])
        self.store.save()

    def rebaseline(self) -> None:
        self.store.reset_baseline()
        self.alerts.ack(None)
        self.wake_sec.set()
        self.wake_trace.set()
